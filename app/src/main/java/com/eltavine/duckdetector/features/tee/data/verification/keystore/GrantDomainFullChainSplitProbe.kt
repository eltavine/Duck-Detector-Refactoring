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
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.nio.charset.StandardCharsets
import java.util.Locale

class GrantDomainFullChainSplitProbe(
    context: Context,
    private val granteeManager: TeeGrantDomainGranteeManager = TeeGrantDomainGranteeManager(context),
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
                // Run the standard Java API first, then retry through HiddenApiBypass when the same
                // KeyStoreManager grant methods exist below the public SDK surface.
                // 先走标准 Java API；若同一组 KeyStoreManager grant 方法存在但低于公开 SDK 表面，再通过 HiddenApiBypass 重试。
                val publicResult = inspectJavaApi(
                    apiResult = KeyStoreGrantJavaApis.publicApi(appContext),
                    alias = alias,
                    diagnostics = diagnostics,
                )
                diagnostics.add("public-final", publicResult.detail)
                result = publicResult
                if (publicResult.shouldRunHiddenFallback()) {
                    val hiddenResult = inspectJavaApi(
                        apiResult = KeyStoreGrantJavaApis.hiddenApi(appContext),
                        alias = alias,
                        diagnostics = diagnostics,
                    )
                    diagnostics.add("hidden-final", hiddenResult.detail)
                    result = selectFinalResult(publicResult, hiddenResult)
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

    private suspend fun inspectJavaApi(
        apiResult: KeyStoreGrantJavaApiResult,
        alias: String,
        diagnostics: GrantDetectionDiagnosticLog,
    ): GrantDomainFullChainSplitResult {
        apiResult.throwable?.let { diagnostics.addThrowable("${apiResult.stage.lowercase()}-get-service", it) }
        val api = apiResult.api ?: return GrantDomainFullChainSplitResult(
            detail = apiResult.detail,
        )
        val stage = api.stageLabel
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val ownerCertificates = runCatching {
            AndroidKeyStoreTools.readCertificateChain(keyStore, alias)
        }.getOrElse { throwable ->
            diagnostics.addThrowable("${stage.lowercase()}-owner-chain", throwable)
            return GrantDomainFullChainSplitResult(
                detail = "$stage: owner chain unavailable (${describeThrowable(throwable)}).",
            )
        }
        val ownerChain = GrantDomainCertificateChain.fromCertificates(ownerCertificates)
        if (ownerChain.certificates.isEmpty()) {
            return GrantDomainFullChainSplitResult(
                detail = "$stage: owner chain empty.",
            )
        }
        val sessionResult = granteeManager.openSession()
        if (!sessionResult.available || sessionResult.session == null) {
            diagnostics.add("${stage.lowercase()}-session", sessionResult.detail)
            return GrantDomainFullChainSplitResult(
                ownerChainLength = ownerChain.certificates.size,
                detail = "$stage: isolated grantee unavailable.",
            )
        }
        var grantCreated = false
        return sessionResult.session.use { session ->
            try {
                // Once the owner alias has a chain, key-not-found during grant means the grant lookup
                // plane disagrees with the owner plane; keep that as FAIL, not availability noise.
                // owner alias 已有证书链后，grant 阶段 key-not-found 表示授权查找平面与 owner 平面不一致；应保留为 FAIL，而不是可用性噪声。
                val grantId = runCatching {
                    api.grantKeyAccess(alias, session.uid)
                }.getOrElse { throwable ->
                    diagnostics.addThrowable("${stage.lowercase()}-grant", throwable)
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
                        detail = "$stage: grant failed (${describeThrowable(throwable)}).",
                    )
                }
                grantCreated = true
                val granteeResult = session.readGrantedCertificateChainJavaApi(grantId, hiddenApi = stage == "Hidden")
                granteeResult.diagnosticCopyText.takeIf { it.isNotBlank() }?.let(diagnostics::addRaw)
                if (!granteeResult.available) {
                    return@use GrantDomainFullChainSplitResult(
                        ownerChainLength = ownerChain.certificates.size,
                        granteeUid = session.uid,
                        detail = "$stage: readback failed (${visibleGrantDetail(granteeResult.detail)}).",
                    )
                }
                val granteeChain = granteeResult.chain
                if (granteeChain.certificates.isEmpty()) {
                    return@use GrantDomainFullChainSplitResult(
                        ownerChainLength = ownerChain.certificates.size,
                        granteeChainLength = 0,
                        granteeUid = session.uid,
                        detail = "$stage: Domain.GRANT certificate chain empty.",
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
                        "$stage: matched ${comparison.detail}"
                    } else {
                        "$stage: clean (${comparison.detail})"
                    },
                )
            } finally {
                if (grantCreated) {
                    runCatching {
                        api.revokeKeyAccess(alias, session.uid)
                    }.onFailure { throwable ->
                        diagnostics.addThrowable("${stage.lowercase()}-revoke", throwable)
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
            hiddenResult: GrantDomainFullChainSplitResult,
        ): GrantDomainFullChainSplitResult {
            // Hidden Java API is the only fallback for this grant probe; private Binder remains a
            // lower-level tool, but this path intentionally stays at KeyStoreManager semantics.
            // Hidden Java API 是此 grant probe 唯一回退路径；private Binder 仍是底层工具，但这里刻意保持 KeyStoreManager 语义。
            val selected = when {
                hiddenResult.isDanger() -> hiddenResult
                publicResult.isDanger() -> publicResult
                hiddenResult.executed || hiddenResult.available -> hiddenResult
                else -> publicResult
            }
            return selected.copy(
                detail = combineGrantStageDetails(
                    publicDetail = publicResult.detail,
                    fallbackLabel = "Hidden",
                    fallbackDetail = hiddenResult.detail,
                ),
            )
        }
    }
}

private fun GrantDomainFullChainSplitResult.shouldRunHiddenFallback(): Boolean {
    return !isDanger() && !(executed && available)
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
