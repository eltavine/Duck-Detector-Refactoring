/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import android.content.Context
import android.os.Build
import android.security.keystore.KeyProtection
import android.security.keystore.KeyProperties
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale

class ImportKeyRetainedAttestationNarrativeProbe internal constructor(
    private val runtime: Runtime,
    private val aliasFactory: () -> String = { "duck_importkey_retained_${System.nanoTime()}" },
) {

    constructor(
        context: Context,
        binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
    ) : this(AndroidRuntime(context.applicationContext, binderClient))

    fun inspect(): ImportKeyRetainedAttestationNarrativeResult {
        if (!runtime.supported) {
            return unavailable("ImportKey retained narrative probe requires Android 12 or newer.")
        }
        val supportAlias = "${aliasFactory()}_support"
        val attackAlias = "${aliasFactory()}_attack"
        return try {
            // 防误报 gate：先证明本 ROM 对普通 APP alias 的 importKey 路径可用且可观测，再进入攻击态对比。
            // False-positive gate: prove ordinary APP-alias importKey is supported and observable before comparing attack-state narratives.
            val support = runtime.verifyImportSupport(supportAlias)
            if (!support.supported) {
                return unavailable(
                    detail = support.detail,
                    anomalyKind = ImportKeyRetainedAttestationAnomalyKind.IMPORT_UNSUPPORTED,
                    importSupported = false,
                    markerImportBaselineClean = false,
                    postImportLeafMatchesMarker = support.leafMatchesMarker,
                    originLabel = support.originLabel,
                )
            }
            val challenge = ByteArray(CHALLENGE_SIZE_BYTES).also(SecureRandom()::nextBytes)
            val priorChain = runtime.generatePriorAttestedChain(attackAlias, challenge)
            if (priorChain.isEmpty()) {
                return unavailable(
                    detail = "Prior attested chain was unavailable for the importKey probe alias.",
                    importSupported = true,
                    markerImportBaselineClean = true,
                )
            }
            runtime.importMarkerKey(attackAlias)
            // TEES-RS may consume the first getKeyEntry() after framework updateSubcomponents(); read twice to observe the stable post-import state.
            // TEES-RS 可能会在 framework updateSubcomponents() 之后吞掉第一次 getKeyEntry() patch；双读用于观测稳定的 import 后状态。
            val snapshots = runtime.readPostImportMetadataSnapshots(attackAlias)
            if (snapshots.isEmpty()) {
                return unavailable(
                    detail = "Keystore2 getKeyEntry() metadata was unavailable after import.",
                    importSupported = true,
                    markerImportBaselineClean = true,
                    priorChainLength = priorChain.size,
                )
            }
            evaluatePostImportState(
                priorChain = priorChain,
                snapshots = snapshots,
                importedOriginValues = runtime.importedOriginValues,
                generatedOriginValue = runtime.generatedOriginValue,
                importSupported = true,
                markerImportBaselineClean = true,
                originLabel = { value -> runtime.originLabel(value) },
            )
        } catch (throwable: Throwable) {
            unavailable(runtime.describeThrowable(throwable))
        } finally {
            runtime.cleanup(supportAlias)
            runtime.cleanup(attackAlias)
        }
    }

    internal interface Runtime {
        val supported: Boolean
        val importedOriginValues: Set<Int>
        val generatedOriginValue: Int?

        fun generatePriorAttestedChain(alias: String, challenge: ByteArray): List<ByteArray>
        fun importMarkerKey(alias: String)
        fun verifyImportSupport(alias: String): ImportSupportResult
        fun readPostImportMetadataSnapshots(alias: String): List<PostImportMetadata>
        fun cleanup(alias: String)

        fun originLabel(value: Int?): String = when (value) {
            null -> "unknown"
            else -> value.toString()
        }

        fun describeThrowable(throwable: Throwable): String {
            return throwable.message ?: "ImportKey retained narrative probe failed."
        }
    }

    internal data class PostImportMetadata(
        val originValue: Int?,
        val fullChain: List<ByteArray>,
        val leafMatchesMarker: Boolean,
    )

    internal data class ImportSupportResult(
        val supported: Boolean,
        val leafMatchesMarker: Boolean,
        val originValue: Int?,
        val originLabel: String,
        val detail: String,
    )

    private class AndroidRuntime(
        context: Context,
        private val binderClient: Keystore2PrivateBinderClient,
    ) : Runtime {
        private val appContext = context.applicationContext
        private val certificateFactory = CertificateFactory.getInstance("X.509")
        private val keyStore = AndroidKeyStoreTools.loadKeyStore()

        override val supported: Boolean
            get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

        override val importedOriginValues: Set<Int>
            get() = setOfNotNull(
                binderClient.getKeyOriginValue("IMPORTED"),
                binderClient.getKeyOriginValue("SECURELY_IMPORTED"),
                ORIGIN_IMPORTED_FALLBACK,
                ORIGIN_SECURELY_IMPORTED_FALLBACK,
            )

        override val generatedOriginValue: Int?
            get() = binderClient.getKeyOriginValue("GENERATED") ?: ORIGIN_GENERATED_FALLBACK

        override fun generatePriorAttestedChain(alias: String, challenge: ByteArray): List<ByteArray> {
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = "CN=DuckDetector ImportKey Retained, O=Eltavine",
                useStrongBox = false,
                challenge = challenge,
            )
            return AndroidKeyStoreTools.readCertificateChain(keyStore, alias)
                .map(X509Certificate::getEncoded)
        }

        override fun importMarkerKey(alias: String) {
            val fixture = KeyboxFixtureLoader(appContext).load()
            val protection = KeyProtection.Builder(
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
            keyStore.setEntry(
                alias,
                java.security.KeyStore.PrivateKeyEntry(fixture.privateKey, arrayOf(fixture.certificate)),
                protection,
            )
        }

        override fun verifyImportSupport(alias: String): ImportSupportResult {
            importMarkerKey(alias)
            val metadata = readPostImportMetadata(alias)
            val originImported = metadata?.originValue in importedOriginValues
            val leafMatchesMarker = metadata?.leafMatchesMarker == true
            val supported = originImported && leafMatchesMarker
            return ImportSupportResult(
                supported = supported,
                leafMatchesMarker = leafMatchesMarker,
                originValue = metadata?.originValue,
                originLabel = originLabel(metadata?.originValue),
                detail = if (supported) {
                    "origin=${originLabel(metadata.originValue)}, marker import baseline clean."
                } else {
                    "ImportKey support gate failed: origin=${originLabel(metadata?.originValue)}, leafMatchesMarker=$leafMatchesMarker."
                },
            )
        }

        override fun readPostImportMetadataSnapshots(alias: String): List<PostImportMetadata> {
            return listOfNotNull(
                readPostImportMetadata(alias),
                readPostImportMetadata(alias),
            )
        }

        private fun readPostImportMetadata(alias: String): PostImportMetadata? {
            val service = binderClient.getKeystoreService() ?: return null
            val response = binderClient.getKeyEntryResponse(service, binderClient.createKeyDescriptor(alias))
                ?: return null
            val metadata = binderClient.getMetadata(response) ?: return null
            val originTag = binderClient.getTagValue("ORIGIN")
            val originValue = originTag?.let { tag ->
                binderClient.getMetadataAuthorizations(metadata)
                    .firstOrNull { authorization ->
                        authorization?.let(binderClient::getAuthorizationTag) == tag
                    }
                    ?.let { authorization -> binderClient.getAuthorizationIntValue(authorization) }
            }
            val markerLeaf = KeyboxFixtureLoader(appContext).load().certificate.encoded
            val leafBlob = binderClient.getCertificateBlob(response)
            val chainBlob = binderClient.getCertificateChainBlob(response)
            return PostImportMetadata(
                originValue = originValue,
                // Keystore2 stores the leaf separately from the remaining chain; compare the ordered full narrative, not only certificateChain.
                // Keystore2 会把叶证书和剩余链分开放；这里必须比较有序完整叙事，而不是只比较 certificateChain。
                fullChain = buildFullChain(leafBlob, chainBlob),
                leafMatchesMarker = leafBlob?.contentEquals(markerLeaf) == true,
            )
        }

        override fun cleanup(alias: String) {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }

        override fun originLabel(value: Int?): String {
            return when (value) {
                null -> "unknown"
                binderClient.getKeyOriginValue("GENERATED") -> "GENERATED"
                binderClient.getKeyOriginValue("DERIVED") -> "DERIVED"
                binderClient.getKeyOriginValue("IMPORTED") -> "IMPORTED"
                binderClient.getKeyOriginValue("UNKNOWN") -> "UNKNOWN"
                binderClient.getKeyOriginValue("SECURELY_IMPORTED") -> "SECURELY_IMPORTED"
                else -> value.toString()
            }
        }

        override fun describeThrowable(throwable: Throwable): String {
            return binderClient.describeThrowable(throwable)
        }

        private fun buildFullChain(leafBlob: ByteArray?, chainBlob: ByteArray?): List<ByteArray> {
            return listOfNotNull(leafBlob?.takeIf { it.isNotEmpty() }) + parseCertificates(chainBlob)
        }

        private fun parseCertificates(blob: ByteArray?): List<ByteArray> {
            if (blob == null || blob.isEmpty()) {
                return emptyList()
            }
            return runCatching {
                certificateFactory.generateCertificates(ByteArrayInputStream(blob))
                    .filterIsInstance<X509Certificate>()
                    .map(X509Certificate::getEncoded)
            }.getOrDefault(emptyList())
        }
    }

    companion object {
        private const val CHALLENGE_SIZE_BYTES = 32
        private const val ORIGIN_GENERATED_FALLBACK = 0
        private const val ORIGIN_IMPORTED_FALLBACK = 2
        private const val ORIGIN_SECURELY_IMPORTED_FALLBACK = 4

        internal fun evaluatePostImportState(
            priorChain: List<ByteArray>,
            snapshots: List<PostImportMetadata>,
            importedOriginValues: Set<Int> = setOf(
                ORIGIN_IMPORTED_FALLBACK,
                ORIGIN_SECURELY_IMPORTED_FALLBACK,
            ),
            generatedOriginValue: Int? = ORIGIN_GENERATED_FALLBACK,
            importSupported: Boolean = true,
            markerImportBaselineClean: Boolean = true,
            originLabel: (Int?) -> String = { value -> value?.toString() ?: "unknown" },
        ): ImportKeyRetainedAttestationNarrativeResult {
            if (!importSupported) {
                return unavailable(
                    detail = "ImportKey support gate failed before retained narrative comparison.",
                    anomalyKind = ImportKeyRetainedAttestationAnomalyKind.IMPORT_UNSUPPORTED,
                    importSupported = false,
                    markerImportBaselineClean = false,
                )
            }
            val priorFingerprints = fingerprintChain(priorChain)
            if (snapshots.isEmpty()) {
                return unavailable(
                    detail = "Keystore2 getKeyEntry() returned no post-import metadata snapshots.",
                    importSupported = true,
                    markerImportBaselineClean = markerImportBaselineClean,
                    priorChainLength = priorFingerprints.size,
                )
            }
            val evaluated = snapshots.map { snapshot ->
                EvaluatedSnapshot(
                    metadata = snapshot,
                    fingerprints = fingerprintChain(snapshot.fullChain),
                    retained = fingerprintChain(snapshot.fullChain).filter { post ->
                        priorFingerprints.any { prior -> prior.sha256 == post.sha256 }
                    },
                )
            }
            val importedRetained = evaluated.firstOrNull { item ->
                item.metadata.originValue in importedOriginValues && item.retained.isNotEmpty()
            }
            if (importedRetained != null) {
                return matched(
                    anomalyKind = ImportKeyRetainedAttestationAnomalyKind.IMPORTED_RETAINED_PRIOR_CHAIN,
                    priorFingerprints = priorFingerprints,
                    postImportFingerprints = importedRetained.fingerprints,
                    retained = importedRetained.retained,
                    originLabel = originLabel(importedRetained.metadata.originValue),
                    postImportLeafMatchesMarker = importedRetained.metadata.leafMatchesMarker,
                    detailPrefix = "kind=IMPORTED_RETAINED_PRIOR_CHAIN",
                )
            }
            val staleGenerated = evaluated.firstOrNull { item ->
                item.metadata.originValue == generatedOriginValue && item.retained.isNotEmpty()
            }
            if (staleGenerated != null) {
                // TEES-RS stale-cache variant: import support was proven, but getKeyEntry still replays the previous GENERATED attestation story.
                // TEES-RS stale-cache 变体：import 支持已被 gate 证明，但 getKeyEntry 仍回放旧 GENERATED 认证叙事。
                return matched(
                    anomalyKind = ImportKeyRetainedAttestationAnomalyKind.STALE_GENERATED_AFTER_IMPORT,
                    priorFingerprints = priorFingerprints,
                    postImportFingerprints = staleGenerated.fingerprints,
                    retained = staleGenerated.retained,
                    originLabel = originLabel(staleGenerated.metadata.originValue),
                    postImportLeafMatchesMarker = staleGenerated.metadata.leafMatchesMarker,
                    detailPrefix = "kind=STALE_GENERATED_AFTER_IMPORT",
                )
            }
            val cleanImported = evaluated.firstOrNull { item ->
                item.metadata.originValue in importedOriginValues && item.metadata.leafMatchesMarker
            }
            if (cleanImported != null) {
                return ImportKeyRetainedAttestationNarrativeResult(
                    executed = true,
                    importSupported = true,
                    markerImportBaselineClean = markerImportBaselineClean,
                    originImported = true,
                    postImportLeafMatchesMarker = true,
                    retainedNarrativeDetected = false,
                    priorChainLength = priorFingerprints.size,
                    postImportChainLength = cleanImported.fingerprints.size,
                    retainedCertificateCount = 0,
                    originLabel = originLabel(cleanImported.metadata.originValue),
                    anomalyKind = ImportKeyRetainedAttestationAnomalyKind.NONE,
                    detail = "kind=NONE, origin=${originLabel(cleanImported.metadata.originValue)}, imported marker leaf returned without retained prior narrative.",
                )
            }
            val representative = evaluated.firstOrNull()
            return unavailable(
                detail = "Post-import metadata did not produce an imported marker baseline or retained prior narrative: origin=${originLabel(representative?.metadata?.originValue)}, leafMatchesMarker=${representative?.metadata?.leafMatchesMarker == true}.",
                importSupported = true,
                markerImportBaselineClean = markerImportBaselineClean,
                priorChainLength = priorFingerprints.size,
                postImportChainLength = representative?.fingerprints?.size ?: 0,
                originLabel = originLabel(representative?.metadata?.originValue),
                postImportLeafMatchesMarker = representative?.metadata?.leafMatchesMarker == true,
            )
        }

        private fun matched(
            anomalyKind: ImportKeyRetainedAttestationAnomalyKind,
            priorFingerprints: List<CertificateFingerprint>,
            postImportFingerprints: List<CertificateFingerprint>,
            retained: List<CertificateFingerprint>,
            originLabel: String,
            postImportLeafMatchesMarker: Boolean,
            detailPrefix: String,
        ): ImportKeyRetainedAttestationNarrativeResult {
            return ImportKeyRetainedAttestationNarrativeResult(
                executed = true,
                importSupported = true,
                markerImportBaselineClean = true,
                originImported = anomalyKind == ImportKeyRetainedAttestationAnomalyKind.IMPORTED_RETAINED_PRIOR_CHAIN,
                postImportLeafMatchesMarker = postImportLeafMatchesMarker,
                retainedNarrativeDetected = true,
                priorChainLength = priorFingerprints.size,
                postImportChainLength = postImportFingerprints.size,
                retainedCertificateCount = retained.size,
                originLabel = originLabel,
                anomalyKind = anomalyKind,
                retainedFingerprint = retained.first().shortSha256,
                detail = "$detailPrefix, origin=$originLabel, retained=${retained.size}, priorChain=${priorFingerprints.size}, postImportChain=${postImportFingerprints.size}, leafMatchesMarker=$postImportLeafMatchesMarker, firstRetained=${retained.first().shortSha256}.",
            )
        }

        private fun unavailable(
            detail: String,
            anomalyKind: ImportKeyRetainedAttestationAnomalyKind = ImportKeyRetainedAttestationAnomalyKind.UNAVAILABLE,
            importSupported: Boolean = false,
            markerImportBaselineClean: Boolean = false,
            postImportLeafMatchesMarker: Boolean = false,
            priorChainLength: Int = 0,
            postImportChainLength: Int = 0,
            originLabel: String = "unknown",
        ): ImportKeyRetainedAttestationNarrativeResult {
            return ImportKeyRetainedAttestationNarrativeResult(
                executed = false,
                importSupported = importSupported,
                markerImportBaselineClean = markerImportBaselineClean,
                originImported = false,
                postImportLeafMatchesMarker = postImportLeafMatchesMarker,
                retainedNarrativeDetected = false,
                priorChainLength = priorChainLength,
                postImportChainLength = postImportChainLength,
                retainedCertificateCount = 0,
                originLabel = originLabel,
                anomalyKind = anomalyKind,
                detail = detail,
            )
        }

        private fun fingerprintChain(chain: List<ByteArray>): List<CertificateFingerprint> {
            return chain.mapIndexed { index, der ->
                val sha256 = der.sha256Hex()
                CertificateFingerprint(
                    index = index,
                    derLength = der.size,
                    sha256 = sha256,
                    shortSha256 = sha256.take(12),
                )
            }
        }

        private fun ByteArray.sha256Hex(): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(this)
            return digest.joinToString(separator = "") { byte ->
                "%02x".format(Locale.US, byte)
            }
        }
    }
}

enum class ImportKeyRetainedAttestationAnomalyKind {
    NONE,
    IMPORT_UNSUPPORTED,
    IMPORTED_RETAINED_PRIOR_CHAIN,
    // Import support was proven separately; GENERATED plus prior-chain overlap means a stale attestation narrative was replayed after overwrite.
    // 已经单独证明 import 支持；GENERATED 且与旧链重叠表示覆盖后仍回放了陈旧认证叙事。
    STALE_GENERATED_AFTER_IMPORT,
    UNAVAILABLE,
}

data class ImportKeyRetainedAttestationNarrativeResult(
    val executed: Boolean,
    val importSupported: Boolean = false,
    val markerImportBaselineClean: Boolean = false,
    val originImported: Boolean = false,
    val postImportLeafMatchesMarker: Boolean = false,
    val retainedNarrativeDetected: Boolean = false,
    val priorChainLength: Int = 0,
    val postImportChainLength: Int = 0,
    val retainedCertificateCount: Int = 0,
    val originLabel: String = "unknown",
    val anomalyKind: ImportKeyRetainedAttestationAnomalyKind = ImportKeyRetainedAttestationAnomalyKind.UNAVAILABLE,
    val retainedFingerprint: String? = null,
    val detail: String,
)

private data class EvaluatedSnapshot(
    val metadata: ImportKeyRetainedAttestationNarrativeProbe.PostImportMetadata,
    val fingerprints: List<CertificateFingerprint>,
    val retained: List<CertificateFingerprint>,
)

private data class CertificateFingerprint(
    val index: Int,
    val derLength: Int,
    val sha256: String,
    val shortSha256: String,
)
