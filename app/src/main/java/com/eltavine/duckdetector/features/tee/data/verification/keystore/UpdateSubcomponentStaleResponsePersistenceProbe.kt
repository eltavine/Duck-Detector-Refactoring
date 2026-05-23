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
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.io.ByteArrayInputStream
import java.security.Key
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale

class UpdateSubcomponentStaleResponsePersistenceProbe internal constructor(
    private val runtime: Runtime,
    private val aliasFactory: () -> String = { "duck_update_persistence_${System.nanoTime()}" },
) {

    constructor(
        context: Context,
        binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
    ) : this(AndroidRuntime(context.applicationContext, binderClient))

    fun inspect(useStrongBox: Boolean = false): UpdateSubcomponentStaleResponsePersistenceResult {
        val supportAlias = "${aliasFactory()}_support"
        val attackAlias = "${aliasFactory()}_attack"
        return try {
            // Support gate: prove getKeyEntry(alias) can observe a freshly written marker certificate before judging stale cache.
            // 防误报 gate：先证明 getKeyEntry(alias) 能观测 fresh marker 证书，再判断 stale cache。
            val support = runtime.verifyCertificateUpdateObservability(supportAlias)
            if (!support.clean) {
                return unavailable(
                    detail = support.detail,
                    anomalyKind = UpdateSubcomponentStaleResponseAnomalyKind.UPDATE_SUBCOMPONENT_UNOBSERVABLE,
                    supportGateClean = false,
                    postLeafMatchesMarker = support.leafMatchesMarker,
                )
            }

            val challenge = ByteArray(CHALLENGE_SIZE_BYTES).also(SecureRandom()::nextBytes)
            val priorChain = runtime.generatePriorAttestedChain(attackAlias, challenge, useStrongBox)
            if (priorChain.isEmpty()) {
                return unavailable(
                    detail = "Prior attested chain was unavailable for updateSubcomponent persistence probe.",
                    supportGateClean = true,
                )
            }
            val key = runtime.readExistingKey(attackAlias) ?: return unavailable(
                detail = "Generated alias did not return an AndroidKeyStore private key for update.",
                supportGateClean = true,
                priorChainLength = priorChain.size,
            )

            val updateDetail = runtime.updateExistingKeyWithMarker(attackAlias, key)
            if (!updateDetail.succeeded) {
                return unavailable(
                    detail = updateDetail.detail,
                    anomalyKind = UpdateSubcomponentStaleResponseAnomalyKind.UPDATE_FAILED,
                    supportGateClean = true,
                    updateSucceeded = false,
                    priorChainLength = priorChain.size,
                )
            }

            // TEES-RS may let the first post-update read see a transient path; use the final read as the stable narrative.
            // TEES-RS 可能让第一次 update 后读取落到暂态路径；用最后一次读取作为稳定叙事。
            val snapshots = runtime.readPostUpdateMetadataSnapshots(attackAlias)
            if (snapshots.isEmpty()) {
                return unavailable(
                    detail = "Keystore2 getKeyEntry() metadata was unavailable after updateSubcomponent.",
                    supportGateClean = true,
                    updateSucceeded = true,
                    priorChainLength = priorChain.size,
                )
            }

            evaluatePostUpdateState(
                priorChain = priorChain,
                snapshots = snapshots,
                supportGateClean = true,
                updateSucceeded = true,
            )
        } catch (throwable: Throwable) {
            unavailable(runtime.describeThrowable(throwable))
        } finally {
            runtime.cleanup(supportAlias)
            runtime.cleanup(attackAlias)
        }
    }

    internal interface Runtime {
        fun verifyCertificateUpdateObservability(alias: String): CertificateUpdateSupportResult
        fun generatePriorAttestedChain(alias: String, challenge: ByteArray, useStrongBox: Boolean): List<ByteArray>
        fun readExistingKey(alias: String): Key?
        fun updateExistingKeyWithMarker(alias: String, key: Key): UpdateAttemptResult
        fun readPostUpdateMetadataSnapshots(alias: String): List<PostUpdateMetadata>
        fun cleanup(alias: String)

        fun describeThrowable(throwable: Throwable): String {
            return throwable.message ?: "UpdateSubcomponent stale response persistence probe failed."
        }
    }

    internal data class CertificateUpdateSupportResult(
        val clean: Boolean,
        val leafMatchesMarker: Boolean,
        val detail: String,
    )

    internal data class UpdateAttemptResult(
        val succeeded: Boolean,
        val detail: String,
    )

    internal data class PostUpdateMetadata(
        val fullChain: List<ByteArray>,
        val leafMatchesMarker: Boolean,
    )

    private class AndroidRuntime(
        context: Context,
        private val binderClient: Keystore2PrivateBinderClient,
    ) : Runtime {
        private val appContext = context.applicationContext
        private val keyStore = AndroidKeyStoreTools.loadKeyStore()
        private val certificateFactory = CertificateFactory.getInstance("X.509")

        override fun verifyCertificateUpdateObservability(alias: String): CertificateUpdateSupportResult {
            val marker = markerCertificate()
            keyStore.setCertificateEntry(alias, marker)
            val metadata = readMetadata(alias)
            val leafMatchesMarker = metadata?.leafMatchesMarker == true
            return CertificateUpdateSupportResult(
                clean = leafMatchesMarker,
                leafMatchesMarker = leafMatchesMarker,
                detail = if (leafMatchesMarker) {
                    "marker certificate baseline clean."
                } else {
                    "UpdateSubcomponent support gate failed: leafMatchesMarker=$leafMatchesMarker."
                },
            )
        }

        override fun generatePriorAttestedChain(
            alias: String,
            challenge: ByteArray,
            useStrongBox: Boolean,
        ): List<ByteArray> {
            AndroidKeyStoreTools.generateAttestedEcChain(
                keyStore = keyStore,
                alias = alias,
                challenge = challenge,
                useStrongBox = useStrongBox,
            )
            return AndroidKeyStoreTools.readCertificateChain(keyStore, alias)
                .map(X509Certificate::getEncoded)
        }

        override fun readExistingKey(alias: String): Key? {
            return keyStore.getKey(alias, null)
        }

        override fun updateExistingKeyWithMarker(alias: String, key: Key): UpdateAttemptResult {
            return runCatching {
                // Existing AndroidKeyStorePrivateKey is important: framework converts this path to KEY_ID + alias=null updateSubcomponents.
                // 这里必须使用已有 AndroidKeyStorePrivateKey：framework 会把该路径转换成 KEY_ID + alias=null 的 updateSubcomponents。
                keyStore.setKeyEntry(alias, key, null, arrayOf<Certificate>(markerCertificate()))
                UpdateAttemptResult(
                    succeeded = true,
                    detail = "setKeyEntry(existing AndroidKeyStorePrivateKey, markerChain) completed.",
                )
            }.getOrElse { throwable ->
                UpdateAttemptResult(
                    succeeded = false,
                    detail = "setKeyEntry(existing AndroidKeyStorePrivateKey, markerChain) failed: ${describeThrowable(throwable)}",
                )
            }
        }

        override fun readPostUpdateMetadataSnapshots(alias: String): List<PostUpdateMetadata> {
            return listOfNotNull(readMetadata(alias), readMetadata(alias))
        }

        override fun cleanup(alias: String) {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }

        override fun describeThrowable(throwable: Throwable): String {
            return binderClient.describeThrowable(throwable)
        }

        private fun readMetadata(alias: String): PostUpdateMetadata? {
            val service = binderClient.getKeystoreService() ?: return null
            val response = binderClient.getKeyEntryResponse(service, binderClient.createKeyDescriptor(alias))
                ?: return null
            val leafBlob = binderClient.getCertificateBlob(response)
            val chainBlob = binderClient.getCertificateChainBlob(response)
            val markerLeaf = markerCertificate().encoded
            val fullChain = buildFullChain(leafBlob, chainBlob)
            return PostUpdateMetadata(
                // Keystore2 stores leaf and remainder separately; stale TEES cache may replay either side.
                // Keystore2 分开保存叶证书和剩余链；TEES stale cache 可能只回放其中一侧。
                fullChain = fullChain,
                leafMatchesMarker = leafBlob?.contentEquals(markerLeaf) == true ||
                    fullChain.firstOrNull()?.contentEquals(markerLeaf) == true,
            )
        }

        private fun markerCertificate(): X509Certificate {
            return KeyboxFixtureLoader(appContext).load().certificate
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

        internal fun evaluatePostUpdateState(
            priorChain: List<ByteArray>,
            snapshots: List<PostUpdateMetadata>,
            supportGateClean: Boolean = true,
            updateSucceeded: Boolean = true,
        ): UpdateSubcomponentStaleResponsePersistenceResult {
            val priorFingerprints = fingerprintChain(priorChain)
            val finalSnapshot = snapshots.lastOrNull()
                ?: return unavailable(
                    detail = "Keystore2 getKeyEntry() returned no post-update metadata snapshots.",
                    supportGateClean = supportGateClean,
                    updateSucceeded = updateSucceeded,
                    priorChainLength = priorFingerprints.size,
                )
            val postFingerprints = fingerprintChain(finalSnapshot.fullChain)
            val retained = postFingerprints.filter { post ->
                priorFingerprints.any { prior -> prior.sha256 == post.sha256 }
            }
            if (retained.isNotEmpty()) {
                return UpdateSubcomponentStaleResponsePersistenceResult(
                    executed = true,
                    available = true,
                    supportGateClean = supportGateClean,
                    updateSucceeded = updateSucceeded,
                    staleNarrativeDetected = true,
                    priorChainLength = priorFingerprints.size,
                    postChainLength = postFingerprints.size,
                    retainedCertificateCount = retained.size,
                    postLeafMatchesMarker = finalSnapshot.leafMatchesMarker,
                    anomalyKind = UpdateSubcomponentStaleResponseAnomalyKind.STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE,
                    retainedFingerprint = retained.first().shortSha256,
                    detail = "kind=STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE, retained=${retained.size}, priorChain=${priorFingerprints.size}, postChain=${postFingerprints.size}, leafMatchesMarker=${finalSnapshot.leafMatchesMarker}, firstRetained=${retained.first().shortSha256}.",
                )
            }
            if (finalSnapshot.leafMatchesMarker) {
                return UpdateSubcomponentStaleResponsePersistenceResult(
                    executed = true,
                    available = true,
                    supportGateClean = supportGateClean,
                    updateSucceeded = updateSucceeded,
                    staleNarrativeDetected = false,
                    priorChainLength = priorFingerprints.size,
                    postChainLength = postFingerprints.size,
                    retainedCertificateCount = 0,
                    postLeafMatchesMarker = true,
                    anomalyKind = UpdateSubcomponentStaleResponseAnomalyKind.NONE,
                    detail = "kind=NONE, marker leaf returned without retained prior narrative.",
                )
            }
            return unavailable(
                detail = "Post-update metadata did not return marker leaf or retained prior narrative: leafMatchesMarker=${finalSnapshot.leafMatchesMarker}, postChain=${postFingerprints.size}.",
                supportGateClean = supportGateClean,
                updateSucceeded = updateSucceeded,
                priorChainLength = priorFingerprints.size,
                postChainLength = postFingerprints.size,
                postLeafMatchesMarker = finalSnapshot.leafMatchesMarker,
            )
        }

        private fun unavailable(
            detail: String,
            anomalyKind: UpdateSubcomponentStaleResponseAnomalyKind = UpdateSubcomponentStaleResponseAnomalyKind.UNAVAILABLE,
            supportGateClean: Boolean = false,
            updateSucceeded: Boolean = false,
            priorChainLength: Int = 0,
            postChainLength: Int = 0,
            postLeafMatchesMarker: Boolean = false,
        ): UpdateSubcomponentStaleResponsePersistenceResult {
            return UpdateSubcomponentStaleResponsePersistenceResult(
                executed = false,
                available = false,
                supportGateClean = supportGateClean,
                updateSucceeded = updateSucceeded,
                staleNarrativeDetected = false,
                priorChainLength = priorChainLength,
                postChainLength = postChainLength,
                retainedCertificateCount = 0,
                postLeafMatchesMarker = postLeafMatchesMarker,
                anomalyKind = anomalyKind,
                detail = detail,
            )
        }

        private fun fingerprintChain(chain: List<ByteArray>): List<UpdateSubcomponentCertificateFingerprint> {
            return chain.mapIndexed { index, der ->
                val sha256 = der.sha256Hex()
                UpdateSubcomponentCertificateFingerprint(
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
                "%02x".format(Locale.US, byte.toInt() and 0xff)
            }
        }
    }
}

enum class UpdateSubcomponentStaleResponseAnomalyKind {
    NONE,
    UPDATE_SUBCOMPONENT_UNOBSERVABLE,
    STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE,
    UPDATE_FAILED,
    UNAVAILABLE,
}

data class UpdateSubcomponentStaleResponsePersistenceResult(
    val executed: Boolean = false,
    val available: Boolean = false,
    val supportGateClean: Boolean = false,
    val updateSucceeded: Boolean = false,
    val staleNarrativeDetected: Boolean = false,
    val priorChainLength: Int = 0,
    val postChainLength: Int = 0,
    val retainedCertificateCount: Int = 0,
    val postLeafMatchesMarker: Boolean = false,
    val anomalyKind: UpdateSubcomponentStaleResponseAnomalyKind = UpdateSubcomponentStaleResponseAnomalyKind.UNAVAILABLE,
    val retainedFingerprint: String? = null,
    val detail: String = "",
)

private data class UpdateSubcomponentCertificateFingerprint(
    val index: Int,
    val derLength: Int,
    val sha256: String,
    val shortSha256: String,
)
