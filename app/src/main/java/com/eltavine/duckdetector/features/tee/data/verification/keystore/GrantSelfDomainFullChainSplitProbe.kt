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
import android.os.Process
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.nio.charset.StandardCharsets

class GrantSelfDomainFullChainSplitProbe(
    context: Context,
) {

    private val appContext = context.applicationContext

    suspend fun inspect(useStrongBox: Boolean): GrantSelfDomainFullChainSplitResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return GrantSelfDomainFullChainSplitResult(
                detail = "Grant self-domain private binder probe requires Android 12 or newer.",
            )
        }
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duck_grant_self_domain_${System.nanoTime()}"
        val selfUid = Process.myUid()
        var result = GrantSelfDomainFullChainSplitResult()
        val diagnostics = GrantDetectionDiagnosticLog(
            title = "Grant self-domain diagnostic alias=$alias uid=$selfUid",
        )
        try {
            val generationFailure = runCatching {
                AndroidKeyStoreTools.generateAttestedEcChain(
                    keyStore = keyStore,
                    alias = alias,
                    challenge = "duck_grant_self_domain_${System.nanoTime()}".toByteArray(StandardCharsets.UTF_8),
                    useStrongBox = useStrongBox,
                )
            }.exceptionOrNull()
            if (generationFailure != null) {
                diagnostics.addThrowable("owner-generate", generationFailure)
                result = GrantSelfDomainFullChainSplitResult(
                    detail = "Owner attested key generation failed: ${GrantDomainFullChainSplitProbe.describeThrowable(generationFailure)}",
                    diagnosticCopyText = diagnostics.text(),
                )
            } else {
                // Prefer the platform Java grant contract, then force the same Java-layer API through
                // HiddenApiBypass on releases where the methods exist but are not public.
                // 优先使用平台 Java grant 契约；若系统版本中方法存在但未公开，再通过 HiddenApiBypass 强制走同一 Java 层 API。
                val publicResult = inspectJavaApi(
                    apiResult = KeyStoreGrantJavaApis.publicApi(appContext),
                    alias = alias,
                    selfUid = selfUid,
                    diagnostics = diagnostics,
                )
                diagnostics.add("public-final", publicResult.detail)
                result = publicResult
                if (publicResult.shouldRunHiddenFallback()) {
                    val hiddenResult = inspectJavaApi(
                        apiResult = KeyStoreGrantJavaApis.hiddenApi(appContext),
                        alias = alias,
                        selfUid = selfUid,
                        diagnostics = diagnostics,
                    )
                    diagnostics.add("hidden-final", hiddenResult.detail)
                    result = selectFinalResult(publicResult, hiddenResult)
                }
                result = result.copy(diagnosticCopyText = diagnostics.text())
            }
        } catch (throwable: Throwable) {
            diagnostics.addThrowable("probe-failure", throwable)
            result = GrantSelfDomainFullChainSplitResult(
                detail = "Grant self-domain full-chain split probe failed: ${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}",
                diagnosticCopyText = diagnostics.text(),
            )
        } finally {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
        return result
    }

    private fun inspectJavaApi(
        apiResult: KeyStoreGrantJavaApiResult,
        alias: String,
        selfUid: Int,
        diagnostics: GrantDetectionDiagnosticLog,
    ): GrantSelfDomainFullChainSplitResult {
        apiResult.throwable?.let { diagnostics.addThrowable("${apiResult.stage.lowercase()}-get-service", it) }
        val api = apiResult.api ?: return GrantSelfDomainFullChainSplitResult(
            detail = apiResult.detail,
        )
        val stage = api.stageLabel
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val ownerCertificates = runCatching {
            AndroidKeyStoreTools.readCertificateChain(keyStore, alias)
        }.getOrElse { throwable ->
            diagnostics.addThrowable("${stage.lowercase()}-owner-chain", throwable)
            return GrantSelfDomainFullChainSplitResult(
                detail = "$stage: owner chain unavailable (${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}).",
            )
        }
        val ownerChain = GrantDomainCertificateChain.fromCertificates(ownerCertificates)
        if (ownerChain.certificates.isEmpty()) {
            return GrantSelfDomainFullChainSplitResult(
                detail = "$stage: owner chain empty.",
            )
        }
        var grantCreated = false
        return try {
            // The owner chain was already readable. A key-not-found at grant time is therefore a
            // visibility divergence, not ordinary probe unavailability.
            // owner chain 已经可读；grant 时 key-not-found 是可见性分歧，不是普通不可用。
            val grantId = runCatching {
                api.grantKeyAccess(alias, selfUid)
            }.getOrElse { throwable ->
                diagnostics.addThrowable("${stage.lowercase()}-grant", throwable)
                val anomalyKind = if (GrantDomainFullChainSplitProbe.isGrantAliasNotFound(throwable)) {
                    GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN
                } else {
                    GrantSelfDomainAnomalyKind.UNAVAILABLE
                }
                return GrantSelfDomainFullChainSplitResult(
                    executed = anomalyKind == GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
                    ownerChainLength = ownerChain.certificates.size,
                    anomalyKind = anomalyKind,
                    detail = "$stage: grant failed (${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}).",
                )
            }
            grantCreated = true
            val grantCertificates = runCatching {
                api.getGrantedCertificateChainFromId(grantId)
            }.getOrElse { throwable ->
                diagnostics.addThrowable("${stage.lowercase()}-read-grant", throwable)
                return GrantSelfDomainFullChainSplitResult(
                    ownerChainLength = ownerChain.certificates.size,
                    grantIdPresent = true,
                    detail = "$stage: readback failed (${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}).",
                )
            }
            val grantChain = GrantDomainCertificateChain.fromCertificates(grantCertificates)
            if (grantChain.certificates.isEmpty()) {
                return GrantSelfDomainFullChainSplitResult(
                    ownerChainLength = ownerChain.certificates.size,
                    grantChainLength = 0,
                    grantIdPresent = true,
                    detail = "$stage: Domain.GRANT certificate chain empty.",
                )
            }
            val comparison = compareChains(ownerChain, grantChain)
            GrantSelfDomainFullChainSplitResult(
                executed = true,
                available = true,
                splitDetected = comparison.splitDetected,
                ownerChainLength = ownerChain.certificates.size,
                grantChainLength = grantChain.certificates.size,
                mismatchIndex = comparison.mismatchIndex,
                grantIdPresent = true,
                anomalyKind = if (comparison.splitDetected) {
                    GrantSelfDomainAnomalyKind.SELF_CHAIN_SPLIT
                } else {
                    GrantSelfDomainAnomalyKind.NONE
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
                    api.revokeKeyAccess(alias, selfUid)
                }.onFailure { throwable ->
                    diagnostics.addThrowable("${stage.lowercase()}-revoke", throwable)
                }
            }
        }
    }

    companion object {
        internal fun compareChains(
            ownerChain: GrantDomainCertificateChain,
            grantChain: GrantDomainCertificateChain,
        ): GrantDomainFullChainComparison {
            return GrantDomainFullChainSplitProbe.compareChains(ownerChain, grantChain)
        }

        internal fun appendDetail(detail: String, extra: String): String {
            return appendGrantDetail(detail, extra)
        }

        internal fun selectFinalResult(
            publicResult: GrantSelfDomainFullChainSplitResult,
            hiddenResult: GrantSelfDomainFullChainSplitResult,
        ): GrantSelfDomainFullChainSplitResult {
            // Hidden Java API is the fallback for releases where KeyStoreManager grant exists below
            // public SDK. It replaces the private Binder fallback for these grant probes.
            // Hidden Java API 是 KeyStoreManager grant 低于公开 SDK 时的回退路径；这两个 grant probe 不再回退到 private Binder。
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

private fun GrantSelfDomainFullChainSplitResult.shouldRunHiddenFallback(): Boolean {
    return !isDanger() && !(executed && available)
}

private fun GrantSelfDomainFullChainSplitResult.isDanger(): Boolean {
    return anomalyKind == GrantSelfDomainAnomalyKind.SELF_CHAIN_SPLIT ||
        anomalyKind == GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN
}

data class GrantSelfDomainFullChainSplitResult(
    val executed: Boolean = false,
    val available: Boolean = false,
    val splitDetected: Boolean = false,
    val ownerChainLength: Int = 0,
    val grantChainLength: Int = 0,
    val mismatchIndex: Int? = null,
    val grantIdPresent: Boolean = false,
    val anomalyKind: GrantSelfDomainAnomalyKind = GrantSelfDomainAnomalyKind.UNAVAILABLE,
    val detail: String = "",
    val diagnosticCopyText: String = "",
)

enum class GrantSelfDomainAnomalyKind {
    NONE,
    SELF_CHAIN_SPLIT,
    SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
    UNAVAILABLE,
}
