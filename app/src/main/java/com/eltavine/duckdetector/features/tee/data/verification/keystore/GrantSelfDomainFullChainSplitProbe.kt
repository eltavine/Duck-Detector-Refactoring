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
import android.security.keystore.KeyStoreManager
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.nio.charset.StandardCharsets
import java.security.cert.X509Certificate

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
                // Public grant is the platform contract on Android 16+; private Binder is an independent
                // incremental pass, so a public clean/skip must not hide a private-plane split.
                // Android 16+ 的 public grant 是平台契约；private Binder 是独立增量检测，因此 public 绿卡/跳过不能掩盖 private 平面的 split。
                val publicResult = inspectPublic(alias, selfUid, diagnostics)
                diagnostics.add("public-final", publicResult.detail)
                result = publicResult
                if (publicResult.shouldRunPrivateFallback()) {
                    val privateResult = inspectPrivate(alias, selfUid, diagnostics)
                    diagnostics.add("private-final", privateResult.detail)
                    result = selectFinalResult(publicResult, privateResult)
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

    private fun inspectPublic(
        alias: String,
        selfUid: Int,
        diagnostics: GrantDetectionDiagnosticLog,
    ): GrantSelfDomainFullChainSplitResult {
        // Keep Android <16 as an explicit public-stage skip, then let the caller run the Android 12+
        // private Binder stage. This preserves one result object while documenting both planes.
        // Android 16 以下明确记为 public 阶段跳过，再由调用方执行 Android 12+ private Binder 阶段；一个结果里保留两个平面的语义。
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.BAKLAVA) {
            return GrantSelfDomainFullChainSplitResult(
                detail = "Public: unsupported (Android < 16).",
            )
        }
        val keyStoreManager = runCatching {
            appContext.getSystemService(KeyStoreManager::class.java)
        }.getOrElse { throwable ->
            diagnostics.addThrowable("public-get-service", throwable)
            null
        } ?: return GrantSelfDomainFullChainSplitResult(
            detail = "Public: unavailable (KeyStoreManager grant API missing).",
        )
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val ownerCertificates = runCatching {
            AndroidKeyStoreTools.readCertificateChain(keyStore, alias)
        }.getOrElse { throwable ->
            diagnostics.addThrowable("public-owner-chain", throwable)
            return GrantSelfDomainFullChainSplitResult(
                detail = "Public: owner chain unavailable (${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}).",
            )
        }
        val ownerChain = GrantDomainCertificateChain.fromCertificates(ownerCertificates)
        if (ownerChain.certificates.isEmpty()) {
            return GrantSelfDomainFullChainSplitResult(
                detail = "Public: owner chain empty.",
            )
        }
        var grantCreated = false
        return try {
            // The owner chain was already readable. A key-not-found at grant time is therefore a
            // visibility divergence, not ordinary probe unavailability.
            // owner chain 已经可读；grant 时 key-not-found 是可见性分歧，不是普通不可用。
            val grantId = runCatching {
                keyStoreManager.grantKeyAccess(alias, selfUid)
            }.getOrElse { throwable ->
                diagnostics.addThrowable("public-grant", throwable)
                val anomalyKind = if (GrantDomainFullChainSplitProbe.isGrantAliasNotFound(throwable)) {
                    GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN
                } else {
                    GrantSelfDomainAnomalyKind.UNAVAILABLE
                }
                return GrantSelfDomainFullChainSplitResult(
                    executed = anomalyKind == GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
                    ownerChainLength = ownerChain.certificates.size,
                    anomalyKind = anomalyKind,
                    detail = "Public: grant failed (${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}).",
                )
            }
            grantCreated = true
            val grantCertificates = runCatching {
                keyStoreManager.getGrantedCertificateChainFromId(grantId)
                    .filterIsInstance<X509Certificate>()
            }.getOrElse { throwable ->
                diagnostics.addThrowable("public-read-grant", throwable)
                return GrantSelfDomainFullChainSplitResult(
                    ownerChainLength = ownerChain.certificates.size,
                    grantIdPresent = true,
                    detail = "Public: readback failed (${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}).",
                )
            }
            val grantChain = GrantDomainCertificateChain.fromCertificates(grantCertificates)
            if (grantChain.certificates.isEmpty()) {
                return GrantSelfDomainFullChainSplitResult(
                    ownerChainLength = ownerChain.certificates.size,
                    grantChainLength = 0,
                    grantIdPresent = true,
                    detail = "Public: Domain.GRANT certificate chain empty.",
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
                    "Public: matched ${comparison.detail}"
                } else {
                    "Public: clean (${comparison.detail})"
                },
            )
        } finally {
            if (grantCreated) {
                runCatching {
                    keyStoreManager.revokeKeyAccess(alias, selfUid)
                }.onFailure { throwable ->
                    diagnostics.addThrowable("public-revoke", throwable)
                }
            }
        }
    }

    private fun inspectPrivate(
        alias: String,
        selfUid: Int,
        diagnostics: GrantDetectionDiagnosticLog,
    ): GrantSelfDomainFullChainSplitResult {
        // Private fallback talks to the same Keystore2 service through hidden Binder transactions.
        // Visible detail stays short; full throwables are routed through diagnostics/hidden copy only.
        // private fallback 通过 hidden Binder transaction 访问同一个 Keystore2 service；UI 只显示短 detail，完整异常只进入隐藏复制诊断。
        val ownerChainResult = privateGrantClient.readOwnerChain(alias)
        ownerChainResult.throwable?.let { diagnostics.addThrowable("private-owner-chain", it) }
        if (!ownerChainResult.available) {
            return GrantSelfDomainFullChainSplitResult(
                detail = "Private: ${visibleGrantDetail(ownerChainResult.detail).ifBlank { "owner chain unavailable." }}",
            )
        }
        val ownerChain = ownerChainResult.chain
        if (ownerChain.certificates.isEmpty()) {
            return GrantSelfDomainFullChainSplitResult(
                detail = "Private: owner chain empty.",
            )
        }
        var grantCreated = false
        return try {
            val grantResult = privateGrantClient.grantAliasToUid(alias, selfUid)
            grantResult.throwable?.let { diagnostics.addThrowable("private-grant", it) }
            if (!grantResult.available || grantResult.grantId == null) {
                val anomalyKind = if (grantResult.errorKind == Keystore2PrivateGrantErrorKind.KEY_NOT_FOUND) {
                    GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN
                } else {
                    GrantSelfDomainAnomalyKind.UNAVAILABLE
                }
                return GrantSelfDomainFullChainSplitResult(
                    executed = anomalyKind == GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
                    ownerChainLength = ownerChain.certificates.size,
                    anomalyKind = anomalyKind,
                    detail = "Private: ${visibleGrantDetail(grantResult.detail).ifBlank { "self grant failed." }}",
                )
            }
            val grantId = grantResult.grantId
            grantCreated = true
            val grantChainResult = privateGrantClient.readGrantChain(grantId)
            grantChainResult.throwable?.let { diagnostics.addThrowable("private-read-grant", it) }
            if (!grantChainResult.available) {
                return GrantSelfDomainFullChainSplitResult(
                    ownerChainLength = ownerChain.certificates.size,
                    grantIdPresent = true,
                    detail = "Private: ${visibleGrantDetail(grantChainResult.detail).ifBlank { "grant readback failed." }}",
                )
            }
            val grantChain = grantChainResult.chain
            if (grantChain.certificates.isEmpty()) {
                return GrantSelfDomainFullChainSplitResult(
                    ownerChainLength = ownerChain.certificates.size,
                    grantChainLength = 0,
                    grantIdPresent = true,
                    detail = "Private: Domain.GRANT certificate chain empty.",
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
                    "Private: matched ${comparison.detail}"
                } else {
                    "Private: clean (${comparison.detail})"
                },
            )
        } finally {
            if (grantCreated) {
                val cleanupResult = privateGrantClient.revokeAliasGrant(alias, selfUid)
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
            privateResult: GrantSelfDomainFullChainSplitResult,
        ): GrantSelfDomainFullChainSplitResult {
            // Prefer whichever stage proves danger; otherwise prefer an executed private stage because
            // it is the incremental signal the public API cannot provide on older or hooked devices.
            // 优先保留能证明 danger 的阶段；否则优先保留已执行的 private 阶段，因为这是 public API 在旧系统或 hook 设备上无法提供的增量信号。
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

private fun GrantSelfDomainFullChainSplitResult.shouldRunPrivateFallback(): Boolean {
    return !isDanger()
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
