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

import android.os.Build
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import java.util.Locale

class BinderChainConsistencyProbe(
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
) {

    private val certificateFactory = CertificateFactory.getInstance("X.509")

    fun inspect(): BinderChainConsistencyResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return BinderChainConsistencyResult(
                executed = false,
                detail = "Binder chain consistency probe requires Android 12 or newer.",
            )
        }
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duck_binder_chain_${System.nanoTime()}"
        return runCatching {
            val hookInstalled = KeystoreBinderCaptureHook.installHook()
            if (!hookInstalled) {
                return BinderChainConsistencyResult(
                    executed = false,
                    hookInstalled = false,
                    detail = "Binder capture hook bootstrap failed.",
                )
            }
            val firstCycle = runActiveCycle(keyStore, alias)
            if (!firstCycle.succeeded) {
                return BinderChainConsistencyResult(
                    executed = true,
                    hookInstalled = true,
                    keystoreChainAvailable = firstCycle.keystoreChain.isNotEmpty(),
                    binderMaterialAvailable = firstCycle.binderChain.isNotEmpty() || firstCycle.generateChain.isNotEmpty(),
                    activeProbeRepeated = true,
                    activeProbeSecondCycleSucceeded = false,
                    detail = "cycle1 ${firstCycle.failureLabel}: ${firstCycle.detail}",
                )
            }
            val secondCycle = runActiveCycle(keyStore, alias)
            if (!secondCycle.succeeded) {
                return BinderChainConsistencyResult(
                    executed = true,
                    hookInstalled = true,
                    keystoreChainAvailable = true,
                    binderMaterialAvailable = secondCycle.binderChain.isNotEmpty() || secondCycle.generateChain.isNotEmpty(),
                    activeProbeRepeated = true,
                    activeProbeSecondCycleSucceeded = false,
                    detail = "cycle2 ${secondCycle.failureLabel}: ${secondCycle.detail}",
                )
            }
            val aggregateKeystoreAvailable = firstCycle.keystoreChain.isNotEmpty() && secondCycle.keystoreChain.isNotEmpty()
            val aggregateBinderMaterialAvailable =
                firstCycle.binderChain.isNotEmpty() || firstCycle.generateChain.isNotEmpty() ||
                    secondCycle.binderChain.isNotEmpty() || secondCycle.generateChain.isNotEmpty()
            val suspiciousKeystoreChain =
                firstCycle.suspiciousLeafIssuerSpki || secondCycle.suspiciousLeafIssuerSpki
            val keystoreMatchesGetKeyEntry = firstCycle.keystoreMatchesGetKeyEntry && secondCycle.keystoreMatchesGetKeyEntry
            val generateVsGetKeyEntryLeafMatches =
                firstCycle.generateVsGetKeyEntryLeafMatches && secondCycle.generateVsGetKeyEntryLeafMatches
            val generateVsGetKeyEntryChainMatches =
                firstCycle.generateVsGetKeyEntryChainMatches && secondCycle.generateVsGetKeyEntryChainMatches
            val deleteEntryRemovedAlias = verifyDeleteEntryRemovesAlias(keyStore, alias)
            BinderChainConsistencyResult(
                executed = true,
                hookInstalled = true,
                keystoreChainAvailable = aggregateKeystoreAvailable,
                generateMaterialAvailable =
                    firstCycle.generateChain.isNotEmpty() || secondCycle.generateChain.isNotEmpty(),
                binderMaterialAvailable = aggregateBinderMaterialAvailable,
                suspiciousLeafIssuerSpki = suspiciousKeystoreChain,
                activeProbeRepeated = true,
                activeProbeSecondCycleSucceeded = true,
                leafMatches = firstCycle.leafMatches && secondCycle.leafMatches,
                chainMatches = keystoreMatchesGetKeyEntry,
                generateVsGetKeyEntryLeafMatches = generateVsGetKeyEntryLeafMatches,
                generateVsGetKeyEntryChainMatches = generateVsGetKeyEntryChainMatches,
                deleteEntryRemovedAlias = deleteEntryRemovedAlias,
                keystoreChainLength = secondCycle.keystoreChain.size,
                binderChainLength = secondCycle.binderChain.size,
                detail = buildString {
                    append("cycle1=")
                    append(firstCycle.detail)
                    append(", cycle2=")
                    append(secondCycle.detail)
                    append(", suspiciousLeafIssuerSpki=")
                    append(suspiciousKeystoreChain)
                    append(", deleteEntryRemovedAlias=")
                    append(deleteEntryRemovedAlias)
                },
            )
        }.getOrElse { throwable ->
            BinderChainConsistencyResult(
                executed = true,
                detail = binderClient.describeThrowable(throwable),
            )
        }.also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
            KeystoreBinderCaptureHook.restore()
        }
    }

    private fun runActiveCycle(
        keyStore: java.security.KeyStore,
        alias: String,
    ): ActiveCycleResult {
        val challenge = Date().toString().toByteArray(StandardCharsets.UTF_8)
        runCatching {
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = "CN=DuckDetector Binder Chain, O=Eltavine",
                useStrongBox = false,
                challenge = challenge,
            )
        }.onFailure { throwable ->
            return ActiveCycleResult.failure(
                failureLabel = "generate failed",
                detail = binderClient.describeThrowable(throwable),
            )
        }
        val privateKey = AndroidKeyStoreTools.readPrivateKey(keyStore, alias)
            ?: return ActiveCycleResult.failure(
                failureLabel = "private key missing",
                detail = "AndroidKeyStore returned no private key for the probe alias.",
            )
        runCatching {
            AndroidKeyStoreTools.signData(privateKey, challenge)
        }.onFailure { throwable ->
            return ActiveCycleResult.failure(
                failureLabel = "sign failed",
                detail = binderClient.describeThrowable(throwable),
            )
        }
        val keystoreChain = AndroidKeyStoreTools.readCertificateChain(keyStore, alias)
        if (keystoreChain.isEmpty()) {
            return ActiveCycleResult.failure(
                failureLabel = "keystore chain unavailable",
                detail = "Java KeyStore returned no certificate chain for the probe alias.",
            )
        }
        val service = binderClient.getKeystoreService()
            ?: return ActiveCycleResult.failure(
                keystoreChain = keystoreChain,
                failureLabel = "keystore2 service unavailable",
                detail = "Keystore2 service interface was unavailable.",
            )
        val response = binderClient.getKeyEntryResponse(service, binderClient.createKeyDescriptor(alias))
            ?: return ActiveCycleResult.failure(
                keystoreChain = keystoreChain,
                failureLabel = "getKeyEntry unavailable",
                detail = "Keystore2 getKeyEntry() returned null for the probe alias.",
            )
        val generateLeaf = KeystoreBinderCaptureHook.getGenerateKeyLeafCertificate(alias)
        val generateChainBlob = KeystoreBinderCaptureHook.getGenerateKeyCertificateChainBlob(alias)
        val keyEntryLeaf = KeystoreBinderCaptureHook.getKeyEntryLeafCertificate(alias)
            ?: binderClient.getCertificateBlob(response)
        val keyEntryChainBlob = KeystoreBinderCaptureHook.getKeyEntryCertificateChainBlob(alias)
            ?: binderClient.getCertificateChainBlob(response)
        val binderChain = buildFullChain(keyEntryLeaf, keyEntryChainBlob)
        val generateChain = buildFullChain(generateLeaf, generateChainBlob)
        if (binderChain.isEmpty() && generateChain.isEmpty()) {
            return ActiveCycleResult.failure(
                keystoreChain = keystoreChain,
                binderChain = binderChain,
                generateChain = generateChain,
                failureLabel = "binder material unavailable",
                detail = "Neither getKeyEntry nor generateKey exposed certificate material for the probe alias.",
            )
        }
        val keystoreDer = keystoreChain.map(X509Certificate::getEncoded)
        val keystoreMatchesGetKeyEntry = when {
            binderChain.isEmpty() -> false
            else -> chainsEqualDer(keystoreDer, binderChain)
        }
        val generateVsGetKeyEntryLeafMatches = when {
            generateLeaf == null || keyEntryLeaf == null -> true
            else -> generateLeaf.contentEquals(keyEntryLeaf)
        }
        val generateVsGetKeyEntryChainMatches = when {
            generateChain.isEmpty() || binderChain.isEmpty() -> true
            else -> chainsEqualDer(generateChain, binderChain)
        }
        return ActiveCycleResult(
            succeeded = true,
            keystoreChain = keystoreChain,
            binderChain = binderChain,
            generateChain = generateChain,
            suspiciousLeafIssuerSpki = hasLeafIssuerSpkiEquality(keystoreChain),
            leafMatches = keystoreDer.firstOrNull()?.let { leaf ->
                binderChain.firstOrNull()?.contentEquals(leaf)
            } == true,
            keystoreMatchesGetKeyEntry = keystoreMatchesGetKeyEntry,
            generateVsGetKeyEntryLeafMatches = generateVsGetKeyEntryLeafMatches,
            generateVsGetKeyEntryChainMatches = generateVsGetKeyEntryChainMatches,
            detail = buildString {
                append("keystoreVsGetKeyEntry=")
                append(keystoreMatchesGetKeyEntry)
                append(", generateVsGetKeyEntryLeaf=")
                append(generateVsGetKeyEntryLeafMatches)
                append(", generateVsGetKeyEntryChain=")
                append(generateVsGetKeyEntryChainMatches)
                append(", keystoreChainLength=")
                append(keystoreChain.size)
                append(", getKeyEntryChainLength=")
                append(binderChain.size)
                if (!keystoreMatchesGetKeyEntry && binderChain.isNotEmpty()) {
                    append(", mismatch=")
                    append(describeChainMismatch(keystoreDer, binderChain))
                }
            },
        )
    }

    private fun hasLeafIssuerSpkiEquality(chain: List<X509Certificate>): Boolean {
        if (chain.size < 2) return false
        val leafSpki = chain[0].publicKey.encoded
        val issuerSpki = chain[1].publicKey.encoded
        return leafSpki.contentEquals(issuerSpki)
    }

    private fun verifyDeleteEntryRemovesAlias(keyStore: java.security.KeyStore, alias: String): Boolean {
        return runCatching {
            if (!keyStore.containsAlias(alias)) {
                true
            } else {
                keyStore.deleteEntry(alias)
                keyStore.load(null)
                !keyStore.containsAlias(alias)
            }
        }.getOrDefault(false)
    }

    private fun buildFullChain(leafDer: ByteArray?, chainBlob: ByteArray?): List<ByteArray> {
        val out = mutableListOf<ByteArray>()
        if (leafDer == null) {
            return out
        }
        out += leafDer
        if (chainBlob == null || chainBlob.isEmpty()) {
            return out
        }
        runCatching {
            val certificates = certificateFactory.generateCertificates(ByteArrayInputStream(chainBlob))
            certificates.filterIsInstance<X509Certificate>().forEach { certificate ->
                val encoded = certificate.encoded
                if (out.none { it.contentEquals(encoded) }) {
                    out += encoded
                }
            }
        }
        return out
    }

    private fun chainsEqualDer(left: List<ByteArray>, right: List<ByteArray>): Boolean {
        return left.size == right.size && left.zip(right).all { (a, b) -> a.contentEquals(b) }
    }

    private fun describeChainMismatch(keystoreChain: List<ByteArray>, otherChain: List<ByteArray>): String {
        val min = minOf(keystoreChain.size, otherChain.size)
        for (index in 0 until min) {
            if (!keystoreChain[index].contentEquals(otherChain[index])) {
                return "mismatchIndex=$index keystoreSerial=${tryGetSerialHex(keystoreChain[index])} binderSerial=${tryGetSerialHex(otherChain[index])}"
            }
        }
        return if (keystoreChain.size != otherChain.size) {
            "lengthMismatch keystore=${keystoreChain.size} binder=${otherChain.size}"
        } else {
            "unknown"
        }
    }

    private fun tryGetSerialHex(certDer: ByteArray): String {
        return runCatching {
            val certificate = certificateFactory.generateCertificate(ByteArrayInputStream(certDer)) as X509Certificate
            certificate.serialNumber.toString(16).lowercase(Locale.US)
        }.getOrDefault("parse_failed")
    }
}

data class BinderChainConsistencyResult(
    val executed: Boolean,
    val hookInstalled: Boolean = false,
    val keystoreChainAvailable: Boolean = false,
    val generateMaterialAvailable: Boolean = false,
    val binderMaterialAvailable: Boolean = false,
    val suspiciousLeafIssuerSpki: Boolean = false,
    val activeProbeRepeated: Boolean = false,
    val activeProbeSecondCycleSucceeded: Boolean = false,
    val leafMatches: Boolean = false,
    val chainMatches: Boolean = false,
    val generateVsGetKeyEntryLeafMatches: Boolean = true,
    val generateVsGetKeyEntryChainMatches: Boolean = true,
    val deleteEntryRemovedAlias: Boolean = true,
    val keystoreChainLength: Int = 0,
    val binderChainLength: Int = 0,
    val detail: String,
)

private data class ActiveCycleResult(
    val succeeded: Boolean,
    val keystoreChain: List<X509Certificate>,
    val binderChain: List<ByteArray>,
    val generateChain: List<ByteArray>,
    val suspiciousLeafIssuerSpki: Boolean,
    val leafMatches: Boolean,
    val keystoreMatchesGetKeyEntry: Boolean,
    val generateVsGetKeyEntryLeafMatches: Boolean,
    val generateVsGetKeyEntryChainMatches: Boolean,
    val failureLabel: String = "",
    val detail: String,
) {
    companion object {
        fun failure(
            keystoreChain: List<X509Certificate> = emptyList(),
            binderChain: List<ByteArray> = emptyList(),
            generateChain: List<ByteArray> = emptyList(),
            failureLabel: String,
            detail: String,
        ): ActiveCycleResult {
            return ActiveCycleResult(
                succeeded = false,
                keystoreChain = keystoreChain,
                binderChain = binderChain,
                generateChain = generateChain,
                suspiciousLeafIssuerSpki = false,
                leafMatches = false,
                keystoreMatchesGetKeyEntry = false,
                generateVsGetKeyEntryLeafMatches = true,
                generateVsGetKeyEntryChainMatches = true,
                failureLabel = failureLabel,
                detail = detail,
            )
        }
    }
}
