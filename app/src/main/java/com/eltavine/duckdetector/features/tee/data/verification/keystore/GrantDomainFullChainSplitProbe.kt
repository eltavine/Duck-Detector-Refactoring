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
import android.os.IBinder
import android.security.keystore.KeyStoreManager
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.nio.charset.StandardCharsets
import java.util.Locale

class GrantDomainFullChainSplitProbe(
    context: Context,
    private val granteeManager: TeeGrantDomainGranteeManager = TeeGrantDomainGranteeManager(context),
    private val privateGrantClient: Keystore2PrivateGrantClient = Keystore2PrivateGrantClient(),
) {

    private val appContext = context.applicationContext

    suspend fun inspect(useStrongBox: Boolean): GrantDomainFullChainSplitResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return GrantDomainFullChainSplitResult(
                detail = "Grant-domain private binder probe requires Android 12 or newer.",
            )
        }
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duck_grant_domain_${System.nanoTime()}"
        var result = GrantDomainFullChainSplitResult()
        val diagnostics = GrantDetectionDiagnosticLog(
            title = "Grant isolated-domain diagnostic alias=$alias",
        )
        try {
            val generationFailure = runCatching {
                AndroidKeyStoreTools.generateAttestedEcChain(
                    keyStore = keyStore,
                    alias = alias,
                    challenge = "duck_grant_domain_${System.nanoTime()}".toByteArray(StandardCharsets.UTF_8),
                    useStrongBox = useStrongBox,
                )
            }.exceptionOrNull()
            if (generationFailure != null) {
                diagnostics.addThrowable("owner-generate", generationFailure)
                result = GrantDomainFullChainSplitResult(
                    detail = "Owner attested key generation failed: ${describeThrowable(generationFailure)}",
                    diagnosticCopyText = diagnostics.text(),
                )
            } else {
                val publicResult = inspectPublic(alias, diagnostics)
                diagnostics.add("public-final", publicResult.detail)
                result = publicResult
                if (publicResult.shouldRunPrivateFallback()) {
                    val privateResult = inspectPrivate(alias, diagnostics)
                    diagnostics.add("private-final", privateResult.detail)
                    result = selectFinalResult(publicResult, privateResult)
                }
                result = result.copy(diagnosticCopyText = diagnostics.text())
            }
        } catch (throwable: Throwable) {
            diagnostics.addThrowable("probe-failure", throwable)
            result = GrantDomainFullChainSplitResult(
                detail = "Grant-domain full-chain split probe failed: ${describeThrowable(throwable)}",
                diagnosticCopyText = diagnostics.text(),
            )
        } finally {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
        return result
    }

    private suspend fun inspectPublic(
        alias: String,
        diagnostics: GrantDetectionDiagnosticLog,
    ): GrantDomainFullChainSplitResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.BAKLAVA) {
            return GrantDomainFullChainSplitResult(
                detail = "Public: unsupported (Android < 16).",
            )
        }
        val keyStoreManager = runCatching {
            appContext.getSystemService(KeyStoreManager::class.java)
        }.getOrElse { throwable ->
            diagnostics.addThrowable("public-get-service", throwable)
            null
        } ?: return GrantDomainFullChainSplitResult(
            detail = "Public: unavailable (KeyStoreManager grant API missing).",
        )
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val ownerCertificates = runCatching {
            AndroidKeyStoreTools.readCertificateChain(keyStore, alias)
        }.getOrElse { throwable ->
            diagnostics.addThrowable("public-owner-chain", throwable)
            return GrantDomainFullChainSplitResult(
                detail = "Public: owner chain unavailable (${describeThrowable(throwable)}).",
            )
        }
        val ownerChain = GrantDomainCertificateChain.fromCertificates(ownerCertificates)
        if (ownerChain.certificates.isEmpty()) {
            return GrantDomainFullChainSplitResult(
                detail = "Public: owner chain empty.",
            )
        }
        val sessionResult = granteeManager.openSession()
        if (!sessionResult.available || sessionResult.session == null) {
            diagnostics.add("public-session", sessionResult.detail)
            return GrantDomainFullChainSplitResult(
                ownerChainLength = ownerChain.certificates.size,
                detail = "Public: isolated grantee unavailable.",
            )
        }
        var grantCreated = false
        return sessionResult.session.use { session ->
            try {
                val grantId = runCatching {
                    keyStoreManager.grantKeyAccess(alias, session.uid)
                }.getOrElse { throwable ->
                    diagnostics.addThrowable("public-grant", throwable)
                    val anomalyKind = if (isGrantAliasNotFound(throwable)) {
                        GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN
                    } else {
                        GrantDomainAnomalyKind.UNAVAILABLE
                    }
                    return@use GrantDomainFullChainSplitResult(
                        executed = anomalyKind == GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
                        ownerChainLength = ownerChain.certificates.size,
                        granteeUid = session.uid,
                        anomalyKind = anomalyKind,
                        detail = "Public: grant failed (${describeThrowable(throwable)}).",
                    )
                }
                grantCreated = true
                val granteeResult = session.readGrantedCertificateChainPublic(grantId)
                granteeResult.diagnosticCopyText.takeIf { it.isNotBlank() }?.let(diagnostics::addRaw)
                if (!granteeResult.available) {
                    return@use GrantDomainFullChainSplitResult(
                        ownerChainLength = ownerChain.certificates.size,
                        granteeUid = session.uid,
                        detail = "Public: readback failed (${visibleGrantDetail(granteeResult.detail)}).",
                    )
                }
                val granteeChain = granteeResult.chain
                if (granteeChain.certificates.isEmpty()) {
                    return@use GrantDomainFullChainSplitResult(
                        ownerChainLength = ownerChain.certificates.size,
                        granteeChainLength = 0,
                        granteeUid = session.uid,
                        detail = "Public: Domain.GRANT certificate chain empty.",
                    )
                }
                val comparison = compareChains(ownerChain, granteeChain)
                GrantDomainFullChainSplitResult(
                    executed = true,
                    available = true,
                    splitDetected = comparison.splitDetected,
                    ownerChainLength = ownerChain.certificates.size,
                    granteeChainLength = granteeChain.certificates.size,
                    mismatchIndex = comparison.mismatchIndex,
                    granteeUid = session.uid,
                    anomalyKind = if (comparison.splitDetected) {
                        GrantDomainAnomalyKind.ISOLATED_CHAIN_SPLIT
                    } else {
                        GrantDomainAnomalyKind.NONE
                    },
                    detail = if (comparison.splitDetected) {
                        "Public: matched ${comparison.detail}"
                    } else {
                        "Public: clean (${comparison.detail})"
                    },
                )
            } finally {
                if (grantCreated) {
                    runCatching {
                        keyStoreManager.revokeKeyAccess(alias, session.uid)
                    }.onFailure { throwable ->
                        diagnostics.addThrowable("public-revoke", throwable)
                    }
                }
            }
        }
    }

    private suspend fun inspectPrivate(
        alias: String,
        diagnostics: GrantDetectionDiagnosticLog,
    ): GrantDomainFullChainSplitResult {
        val keystore2Binder = privateGrantClient.lookupBinder()
            ?: return GrantDomainFullChainSplitResult(
                detail = "Private: keystore2 binder unavailable.",
            )
        val ownerChainResult = privateGrantClient.readOwnerChain(alias)
        ownerChainResult.throwable?.let { diagnostics.addThrowable("private-owner-chain", it) }
        if (!ownerChainResult.available) {
            return GrantDomainFullChainSplitResult(
                detail = "Private: ${visibleGrantDetail(ownerChainResult.detail).ifBlank { "owner chain unavailable." }}",
            )
        }
        val ownerChain = ownerChainResult.chain
        if (ownerChain.certificates.isEmpty()) {
            return GrantDomainFullChainSplitResult(
                detail = "Private: owner chain empty.",
            )
        }
        val sessionResult = granteeManager.openSession()
        if (!sessionResult.available || sessionResult.session == null) {
            diagnostics.add("private-session", sessionResult.detail)
            return GrantDomainFullChainSplitResult(
                ownerChainLength = ownerChain.certificates.size,
                detail = "Private: isolated grantee unavailable.",
            )
        }
        var grantCreated = false
        return sessionResult.session.use { session ->
            try {
                val grantResult = privateGrantClient.grantAliasToUid(alias, session.uid)
                grantResult.throwable?.let { diagnostics.addThrowable("private-grant", it) }
                if (!grantResult.available || grantResult.grantId == null) {
                    val anomalyKind = if (grantResult.errorKind == Keystore2PrivateGrantErrorKind.KEY_NOT_FOUND) {
                        GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN
                    } else {
                        GrantDomainAnomalyKind.UNAVAILABLE
                    }
                    return@use GrantDomainFullChainSplitResult(
                        executed = anomalyKind == GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
                        ownerChainLength = ownerChain.certificates.size,
                        granteeUid = session.uid,
                        anomalyKind = anomalyKind,
                        detail = "Private: ${visibleGrantDetail(grantResult.detail).ifBlank { "isolated grant failed." }}",
                    )
                }
                val grantId = grantResult.grantId
                grantCreated = true
                val granteeResult = session.readGrantedCertificateChain(grantId, keystore2Binder)
                granteeResult.diagnosticCopyText.takeIf { it.isNotBlank() }?.let(diagnostics::addRaw)
                if (!granteeResult.available) {
                    return@use GrantDomainFullChainSplitResult(
                        ownerChainLength = ownerChain.certificates.size,
                        granteeUid = session.uid,
                        detail = "Private: ${visibleGrantDetail(granteeResult.detail).ifBlank { "isolated readback blocked." }}",
                    )
                }
                val granteeChain = granteeResult.chain
                if (granteeChain.certificates.isEmpty()) {
                    return@use GrantDomainFullChainSplitResult(
                        ownerChainLength = ownerChain.certificates.size,
                        granteeChainLength = 0,
                        granteeUid = session.uid,
                        detail = "Private: Domain.GRANT certificate chain empty.",
                    )
                }
                val comparison = compareChains(ownerChain, granteeChain)
                GrantDomainFullChainSplitResult(
                    executed = true,
                    available = true,
                    splitDetected = comparison.splitDetected,
                    ownerChainLength = ownerChain.certificates.size,
                    granteeChainLength = granteeChain.certificates.size,
                    mismatchIndex = comparison.mismatchIndex,
                    granteeUid = session.uid,
                    anomalyKind = if (comparison.splitDetected) {
                        GrantDomainAnomalyKind.ISOLATED_CHAIN_SPLIT
                    } else {
                        GrantDomainAnomalyKind.NONE
                    },
                    detail = if (comparison.splitDetected) {
                        "Private: matched ${comparison.detail}"
                    } else {
                        "Private: clean (${comparison.detail})"
                    },
                )
            } finally {
                if (grantCreated) {
                    val cleanupResult = privateGrantClient.revokeAliasGrant(alias, session.uid)
                    cleanupResult.throwable?.let { diagnostics.addThrowable("private-ungrant", it) }
                    if (!cleanupResult.available) {
                        diagnostics.add(
                            "private-ungrant",
                            cleanupResult.detail.ifBlank { "private ungrant failed." },
                        )
                    }
                }
            }
        }
    }

    companion object {
        internal fun compareChains(
            ownerChain: GrantDomainCertificateChain,
            granteeChain: GrantDomainCertificateChain,
        ): GrantDomainFullChainComparison {
            val owner = ownerChain.certificates
            val grantee = granteeChain.certificates
            val min = minOf(owner.size, grantee.size)
            for (index in 0 until min) {
                if (owner[index] != grantee[index]) {
                    val reason = if (index == 0) "leafMismatch" else "chainMismatch"
                    return GrantDomainFullChainComparison(
                        splitDetected = true,
                        mismatchIndex = index,
                        detail = "$reason index=$index owner=${owner[index].summary()} grantee=${grantee[index].summary()}",
                    )
                }
            }
            if (owner.size != grantee.size) {
                return GrantDomainFullChainComparison(
                    splitDetected = true,
                    mismatchIndex = min,
                    detail = "lengthMismatch owner=${owner.size} grantee=${grantee.size}",
                )
            }
            return GrantDomainFullChainComparison(
                splitDetected = false,
                detail = "Owner alias and grantee Domain.GRANT ordered full-chain fingerprints matched.",
            )
        }

        internal fun describeThrowable(throwable: Throwable): String {
            return GrantThrowableFormatter.describe(throwable)
        }

        internal fun isGrantAliasNotFound(throwable: Throwable): Boolean {
            return GrantThrowableFormatter.isGrantAliasNotFound(throwable)
        }

        internal fun appendDetail(detail: String, extra: String): String {
            return GrantSelfDomainFullChainSplitProbe.appendDetail(detail, extra)
        }

        internal fun selectFinalResult(
            publicResult: GrantDomainFullChainSplitResult,
            privateResult: GrantDomainFullChainSplitResult,
        ): GrantDomainFullChainSplitResult {
            val selected = when {
                privateResult.isDanger() -> privateResult
                publicResult.isDanger() -> publicResult
                privateResult.executed || privateResult.available -> privateResult
                else -> publicResult
            }
            return selected.copy(
                detail = combineGrantStageDetails(
                    publicDetail = publicResult.detail,
                    privateDetail = privateResult.detail,
                ),
            )
        }
    }
}

private fun GrantDomainFullChainSplitResult.shouldRunPrivateFallback(): Boolean {
    return !isDanger()
}

private fun GrantDomainFullChainSplitResult.isDanger(): Boolean {
    return anomalyKind == GrantDomainAnomalyKind.ISOLATED_CHAIN_SPLIT ||
        anomalyKind == GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN
}

data class GrantDomainFullChainSplitResult(
    val executed: Boolean = false,
    val available: Boolean = false,
    val splitDetected: Boolean = false,
    val ownerChainLength: Int = 0,
    val granteeChainLength: Int = 0,
    val mismatchIndex: Int? = null,
    val granteeUid: Int? = null,
    val anomalyKind: GrantDomainAnomalyKind = GrantDomainAnomalyKind.UNAVAILABLE,
    val detail: String = "",
    val diagnosticCopyText: String = "",
)

enum class GrantDomainAnomalyKind {
    NONE,
    ISOLATED_CHAIN_SPLIT,
    ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
    UNAVAILABLE,
}

data class GrantDomainFullChainComparison(
    val splitDetected: Boolean,
    val mismatchIndex: Int? = null,
    val detail: String,
)

data class GrantDomainCertificateChain(
    val certificates: List<GrantDomainCertificateFingerprint> = emptyList(),
) {
    companion object {
        fun fromCertificates(certificates: List<X509Certificate>): GrantDomainCertificateChain {
            return GrantDomainCertificateChain(
                certificates = certificates.map { certificate ->
                    GrantDomainCertificateFingerprint.fromDer(certificate.encoded)
                },
            )
        }
    }
}

data class GrantDomainCertificateFingerprint(
    val derLength: Int,
    val sha256: String,
) {
    fun summary(): String {
        return "len=$derLength sha256=${sha256.take(16)}"
    }

    companion object {
        fun fromDer(der: ByteArray): GrantDomainCertificateFingerprint {
            val digest = MessageDigest.getInstance("SHA-256").digest(der)
            return GrantDomainCertificateFingerprint(
                derLength = der.size,
                sha256 = digest.joinToString(separator = "") { byte ->
                    "%02x".format(Locale.US, byte.toInt() and 0xff)
                },
            )
        }
    }
}
