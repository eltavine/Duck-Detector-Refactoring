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
        val alias = aliasFactory()
        return try {
            val challenge = ByteArray(CHALLENGE_SIZE_BYTES).also(SecureRandom()::nextBytes)
            val priorChain = runtime.generatePriorAttestedChain(alias, challenge)
            if (priorChain.isEmpty()) {
                return unavailable("Prior attested chain was unavailable for the importKey probe alias.")
            }
            runtime.importMarkerKey(alias)
            val metadata = runtime.readPostImportMetadata(alias)
                ?: return unavailable("Keystore2 getKeyEntry() metadata was unavailable after import.")
            evaluatePostImportState(
                priorChain = priorChain,
                postImportChain = metadata.certificateChain,
                originValue = metadata.originValue,
                importedOriginValues = runtime.importedOriginValues,
                originLabel = runtime.originLabel(metadata.originValue),
            )
        } catch (throwable: Throwable) {
            unavailable(runtime.describeThrowable(throwable))
        } finally {
            runtime.cleanup(alias)
        }
    }

    internal interface Runtime {
        val supported: Boolean
        val importedOriginValues: Set<Int>

        fun generatePriorAttestedChain(alias: String, challenge: ByteArray): List<ByteArray>
        fun importMarkerKey(alias: String)
        fun readPostImportMetadata(alias: String): PostImportMetadata?
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
        val certificateChain: List<ByteArray>,
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

        override fun readPostImportMetadata(alias: String): PostImportMetadata? {
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
            val chainBlob = binderClient.getCertificateChainBlob(response)
            return PostImportMetadata(
                originValue = originValue,
                certificateChain = parseCertificates(chainBlob),
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
        private const val ORIGIN_IMPORTED_FALLBACK = 2
        private const val ORIGIN_SECURELY_IMPORTED_FALLBACK = 4

        internal fun evaluatePostImportState(
            priorChain: List<ByteArray>,
            postImportChain: List<ByteArray>,
            originValue: Int?,
            importedOriginValues: Set<Int> = setOf(
                ORIGIN_IMPORTED_FALLBACK,
                ORIGIN_SECURELY_IMPORTED_FALLBACK,
            ),
            originLabel: String = originValue?.toString() ?: "unknown",
        ): ImportKeyRetainedAttestationNarrativeResult {
            val priorFingerprints = fingerprintChain(priorChain)
            val postImportFingerprints = fingerprintChain(postImportChain)
            if (originValue == null || originValue !in importedOriginValues) {
                return unavailable(
                    detail = "Imported key ORIGIN was not established after alias overwrite: origin=$originLabel.",
                    priorChainLength = priorFingerprints.size,
                    postImportChainLength = postImportFingerprints.size,
                    originLabel = originLabel,
                )
            }
            if (postImportFingerprints.isEmpty()) {
                return ImportKeyRetainedAttestationNarrativeResult(
                    executed = true,
                    originImported = true,
                    retainedNarrativeDetected = false,
                    priorChainLength = priorFingerprints.size,
                    postImportChainLength = 0,
                    retainedCertificateCount = 0,
                    originLabel = originLabel,
                    detail = "origin=$originLabel, imported key returned no certificateChain after alias overwrite.",
                )
            }
            val retained = postImportFingerprints.filter { post ->
                priorFingerprints.any { prior -> prior.sha256 == post.sha256 }
            }
            if (retained.isEmpty()) {
                return unavailable(
                    detail = "origin=$originLabel, post-import certificateChain was present but did not match the prior attestation narrative.",
                    priorChainLength = priorFingerprints.size,
                    postImportChainLength = postImportFingerprints.size,
                    originLabel = originLabel,
                )
            }
            return ImportKeyRetainedAttestationNarrativeResult(
                executed = true,
                originImported = true,
                retainedNarrativeDetected = true,
                priorChainLength = priorFingerprints.size,
                postImportChainLength = postImportFingerprints.size,
                retainedCertificateCount = retained.size,
                originLabel = originLabel,
                retainedFingerprint = retained.first().shortSha256,
                detail = "origin=$originLabel, retained=${retained.size}, priorChain=${priorFingerprints.size}, postImportChain=${postImportFingerprints.size}, firstRetained=${retained.first().shortSha256}.",
            )
        }

        private fun unavailable(
            detail: String,
            priorChainLength: Int = 0,
            postImportChainLength: Int = 0,
            originLabel: String = "unknown",
        ): ImportKeyRetainedAttestationNarrativeResult {
            return ImportKeyRetainedAttestationNarrativeResult(
                executed = false,
                originImported = false,
                retainedNarrativeDetected = false,
                priorChainLength = priorChainLength,
                postImportChainLength = postImportChainLength,
                retainedCertificateCount = 0,
                originLabel = originLabel,
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

data class ImportKeyRetainedAttestationNarrativeResult(
    val executed: Boolean,
    val originImported: Boolean = false,
    val retainedNarrativeDetected: Boolean = false,
    val priorChainLength: Int = 0,
    val postImportChainLength: Int = 0,
    val retainedCertificateCount: Int = 0,
    val originLabel: String = "unknown",
    val retainedFingerprint: String? = null,
    val detail: String,
)

private data class CertificateFingerprint(
    val index: Int,
    val derLength: Int,
    val sha256: String,
    val shortSha256: String,
)
