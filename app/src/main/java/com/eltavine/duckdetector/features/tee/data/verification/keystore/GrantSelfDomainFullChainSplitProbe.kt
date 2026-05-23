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
    private val privateGrantClient: Keystore2PrivateGrantClient = Keystore2PrivateGrantClient(),
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
                // Public/hidden Java APIs validate platform KeyStoreManager semantics. When they do
                // not find danger, private Binder runs as an independent incremental plane check.
                // public/hidden Java API 用于验证平台 KeyStoreManager 语义；未发现红卡后，private Binder 作为独立增量平面检测继续执行。
                val publicResult = inspectJavaApi(
                    apiResult = KeyStoreGrantJavaApis.publicApi(appContext),
                    alias = alias,
                    selfUid = selfUid,
                    diagnostics = diagnostics,
                )
                diagnostics.add("public-final", publicResult.detail)
                result = publicResult
                val hiddenResult = if (publicResult.isDanger()) {
                    // A Java-stage danger is already actionable; skip later stages to avoid issuing
                    // duplicate grants that cannot improve the final severity.
                    // Java 阶段已给出可行动红卡时跳过后续阶段，避免重复发起不会提高最终等级的 grant。
                    GrantSelfDomainFullChainSplitResult(
                        detail = "skipped because public stage already detected danger",
                    )
                } else {
                    inspectJavaApi(
                        apiResult = KeyStoreGrantJavaApis.hiddenApi(appContext),
                        alias = alias,
                        selfUid = selfUid,
                        diagnostics = diagnostics,
                    )
                }
                diagnostics.add("hidden-final", hiddenResult.detail)
                val privateResult = if (publicResult.isDanger() || hiddenResult.isDanger()) {
                    // Private Binder is incremental evidence, not a downgrade path. Once Java finds
                    // danger, preserve that finding and only record why the low-level stage skipped.
                    // private Binder 是增量证据而不是降级路径；Java 已发现红卡时保留该结论，只记录底层阶段为何跳过。
                    GrantSelfDomainFullChainSplitResult(
                        detail = "skipped because Java grant stage already detected danger",
                    )
                } else {
                    inspectPrivateBinder(
                        alias = alias,
                        selfUid = selfUid,
                        diagnostics = diagnostics,
                    )
                }
                diagnostics.add("private-final", privateResult.detail)
                result = selectFinalResult(publicResult, hiddenResult, privateResult)
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

    private fun inspectPrivateBinder(
        alias: String,
        selfUid: Int,
        diagnostics: GrantDetectionDiagnosticLog,
    ): GrantSelfDomainFullChainSplitResult {
        val ownerResult = privateGrantClient.readOwnerChain(alias)
        ownerResult.throwable?.let { diagnostics.addThrowable("private-owner-chain", it) }
        if (!ownerResult.available) {
            return GrantSelfDomainFullChainSplitResult(
                detail = ownerResult.detail,
            )
        }
        val ownerChain = ownerResult.chain
        if (ownerChain.certificates.isEmpty()) {
            return GrantSelfDomainFullChainSplitResult(
                detail = "private getKeyEntry(APP) returned an empty certificate chain.",
            )
        }
        var grantCreated = false
        var stageResult = GrantSelfDomainFullChainSplitResult(
            detail = "Private: grant did not complete.",
        )
        try {
            // This grant intentionally bypasses KeyStoreManager so APP alias and GRANT namespace are
            // compared through the same Keystore2 binder surface that hooks often virtualize unevenly.
            // 这里刻意绕过 KeyStoreManager，让 APP alias 与 GRANT namespace 通过同一 Keystore2 binder 表面比较，捕获 hook 常见的不均匀虚拟化。
            val grantResult = privateGrantClient.grantAliasToUid(alias, selfUid)
            grantResult.throwable?.let { diagnostics.addThrowable("private-grant", it) }
            val grantId = grantResult.grantId
            if (!grantResult.available || grantId == null) {
                val anomalyKind = if (grantResult.errorKind == Keystore2PrivateGrantErrorKind.KEY_NOT_FOUND) {
                    GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN
                } else {
                    GrantSelfDomainAnomalyKind.UNAVAILABLE
                }
                return GrantSelfDomainFullChainSplitResult(
                    executed = anomalyKind == GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
                    ownerChainLength = ownerChain.certificates.size,
                    anomalyKind = anomalyKind,
                    detail = grantResult.detail,
                )
            }
            grantCreated = true
            val grantChainResult = privateGrantClient.readGrantChain(grantId)
            grantChainResult.throwable?.let { diagnostics.addThrowable("private-read-grant", it) }
            if (!grantChainResult.available) {
                stageResult = GrantSelfDomainFullChainSplitResult(
                    ownerChainLength = ownerChain.certificates.size,
                    grantIdPresent = true,
                    detail = grantChainResult.detail,
                )
            } else if (grantChainResult.chain.certificates.isEmpty()) {
                stageResult = GrantSelfDomainFullChainSplitResult(
                    ownerChainLength = ownerChain.certificates.size,
                    grantChainLength = 0,
                    grantIdPresent = true,
                    detail = "private getKeyEntry(GRANT) returned an empty certificate chain.",
                )
            } else {
                val grantChain = grantChainResult.chain
                val comparison = compareChains(ownerChain, grantChain)
                stageResult = GrantSelfDomainFullChainSplitResult(
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
                        "Private: matched ${comparison.detail}"
                    } else {
                        "Private: clean (${comparison.detail})"
                    },
                )
            }
        } finally {
            if (grantCreated) {
                // Cleanup is part of the probe contract. If it fails, keep the detection result but
                // append a short visible note and leave the stack trace in hidden diagnostics.
                // cleanup 是检测契约的一部分；失败时保留检测结果，只追加短可见说明，完整堆栈留在隐藏诊断中。
                val ungrantResult = privateGrantClient.revokeAliasGrant(alias, selfUid)
                ungrantResult.throwable?.let { diagnostics.addThrowable("private-revoke", it) }
                if (!ungrantResult.available) {
                    diagnostics.add("private-revoke", ungrantResult.detail)
                    stageResult = stageResult.copy(
                        detail = appendDetail(stageResult.detail, ungrantResult.detail),
                    )
                }
            }
        }
        return stageResult
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
            privateResult: GrantSelfDomainFullChainSplitResult = GrantSelfDomainFullChainSplitResult(),
        ): GrantSelfDomainFullChainSplitResult {
            // Keep the strongest signal, but preserve all stage summaries so a clean Java pass does
            // not hide a lower-level APP/GRANT plane split found by private Binder.
            // 保留最强信号，同时保留所有阶段摘要，避免 Java 绿卡掩盖 private Binder 发现的 APP/GRANT 平面断裂。
            val selected = when {
                privateResult.isDanger() -> privateResult
                hiddenResult.isDanger() -> hiddenResult
                publicResult.isDanger() -> publicResult
                privateResult.executed || privateResult.available -> privateResult
                hiddenResult.executed || hiddenResult.available -> hiddenResult
                else -> publicResult
            }
            return selected.copy(
                detail = combineGrantStageDetails(
                    publicDetail = publicResult.detail,
                    hiddenDetail = hiddenResult.detail,
                    privateDetail = privateResult.detail,
                ),
            )
        }
    }
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
