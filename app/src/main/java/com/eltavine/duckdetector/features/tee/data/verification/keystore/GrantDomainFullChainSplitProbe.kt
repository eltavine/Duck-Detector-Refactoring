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
                // Public/hidden Java APIs validate platform KeyStoreManager semantics. Private Binder
                // then performs an independent isolated readback when Java stages do not find danger.
                // public/hidden Java API 用于验证平台 KeyStoreManager 语义；Java 阶段未发现红卡时，private Binder 继续执行独立 isolated 回读。
                val publicResult = inspectJavaApi(
                    apiResult = KeyStoreGrantJavaApis.publicApi(appContext),
                    alias = alias,
                    diagnostics = diagnostics,
                )
                diagnostics.add("public-final", publicResult.detail)
                result = publicResult
                val hiddenResult = if (publicResult.isDanger()) {
                    // A Java-stage danger is already actionable; skip later stages to avoid issuing
                    // duplicate grants that cannot improve the final severity.
                    // Java 阶段已给出可行动红卡时跳过后续阶段，避免重复发起不会提高最终等级的 grant。
                    GrantDomainFullChainSplitResult(
                        detail = "skipped because public stage already detected danger",
                    )
                } else {
                    inspectJavaApi(
                        apiResult = KeyStoreGrantJavaApis.hiddenApi(appContext),
                        alias = alias,
                        diagnostics = diagnostics,
                    )
                }
                diagnostics.add("hidden-final", hiddenResult.detail)
                val privateResult = if (publicResult.isDanger() || hiddenResult.isDanger()) {
                    // Private Binder is incremental evidence, not a downgrade path. Once Java finds
                    // danger, preserve that finding and only record why the low-level stage skipped.
                    // private Binder 是增量证据而不是降级路径；Java 已发现红卡时保留该结论，只记录底层阶段为何跳过。
                    GrantDomainFullChainSplitResult(
                        detail = "skipped because Java grant stage already detected danger",
                    )
                } else {
                    inspectPrivateBinder(
                        alias = alias,
                        diagnostics = diagnostics,
                    )
                }
                diagnostics.add("private-final", privateResult.detail)
                result = selectFinalResult(publicResult, hiddenResult, privateResult)
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

    private suspend fun inspectPrivateBinder(
        alias: String,
        diagnostics: GrantDetectionDiagnosticLog,
    ): GrantDomainFullChainSplitResult {
        val ownerResult = privateGrantClient.readOwnerChain(alias)
        ownerResult.throwable?.let { diagnostics.addThrowable("private-owner-chain", it) }
        if (!ownerResult.available) {
            return GrantDomainFullChainSplitResult(
                detail = ownerResult.detail,
            )
        }
        val ownerChain = ownerResult.chain
        if (ownerChain.certificates.isEmpty()) {
            return GrantDomainFullChainSplitResult(
                detail = "private getKeyEntry(APP) returned an empty certificate chain.",
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
            var stageResult = GrantDomainFullChainSplitResult(
                detail = "Private: grant did not complete.",
            )
            try {
                // Owner creates the grant, but isolated readback must use the owner-passed Keystore2
                // binder. That keeps the test focused on cross-domain GRANT visibility, not service lookup.
                // grant 由 owner 创建，但 isolated 回读必须使用 owner 传入的 Keystore2 binder；这样检测聚焦跨域 GRANT 可见性，而非服务查找差异。
                val grantResult = privateGrantClient.grantAliasToUid(alias, session.uid)
                grantResult.throwable?.let { diagnostics.addThrowable("private-grant", it) }
                val grantId = grantResult.grantId
                if (!grantResult.available || grantId == null) {
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
                        detail = grantResult.detail,
                    )
                }
                grantCreated = true
                val keystore2Binder = privateGrantClient.lookupBinder()
                if (keystore2Binder == null) {
                    stageResult = GrantDomainFullChainSplitResult(
                        ownerChainLength = ownerChain.certificates.size,
                        granteeUid = session.uid,
                        detail = "isolated binder call blocked: owner keystore2 binder unavailable.",
                    )
                } else {
                    val granteeResult = session.readGrantedCertificateChain(grantId, keystore2Binder)
                    granteeResult.diagnosticCopyText.takeIf { it.isNotBlank() }?.let(diagnostics::addRaw)
                    if (!granteeResult.available) {
                        val stackPayload = diagnostics.text()
                        val crashDetected = matchesPrivateIsolatedCrashSignature(stackPayload)
                        stageResult = GrantDomainFullChainSplitResult(
                            executed = crashDetected,
                            ownerChainLength = ownerChain.certificates.size,
                            granteeUid = session.uid,
                            anomalyKind = if (crashDetected) {
                                GrantDomainAnomalyKind.ISOLATED_PRIVATE_READBACK_CRASH
                            } else {
                                GrantDomainAnomalyKind.UNAVAILABLE
                            },
                            detail = if (crashDetected) {
                                "Private: isolated readback crashed after grant succeeded."
                            } else {
                                "Private: readback failed (${visibleGrantDetail(granteeResult.detail)})."
                            },
                            diagnosticCopyText = if (crashDetected) stackPayload else granteeResult.diagnosticCopyText,
                        )
                    } else if (granteeResult.chain.certificates.isEmpty()) {
                        stageResult = GrantDomainFullChainSplitResult(
                            ownerChainLength = ownerChain.certificates.size,
                            granteeChainLength = 0,
                            granteeUid = session.uid,
                            detail = "Private: Domain.GRANT certificate chain empty.",
                        )
                    } else {
                        val granteeChain = granteeResult.chain
                        val comparison = compareChains(ownerChain, granteeChain)
                        stageResult = GrantDomainFullChainSplitResult(
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
                    }
                }
            } finally {
                if (grantCreated) {
                    // Cleanup is part of the probe contract. If it fails, keep the detection result but
                    // append a short visible note and leave the stack trace in hidden diagnostics.
                    // cleanup 是检测契约的一部分；失败时保留检测结果，只追加短可见说明，完整堆栈留在隐藏诊断中。
                    val ungrantResult = privateGrantClient.revokeAliasGrant(alias, session.uid)
                    ungrantResult.throwable?.let { diagnostics.addThrowable("private-revoke", it) }
                    if (!ungrantResult.available) {
                        diagnostics.add("private-revoke", ungrantResult.detail)
                        stageResult = stageResult.copy(
                            detail = appendDetail(stageResult.detail, ungrantResult.detail),
                        )
                    }
                }
            }
            stageResult
        }
    }

    companion object {
        internal fun matchesPrivateIsolatedCrashSignature(
            stackPayload: String,
        ): Boolean {
            // This matcher promotes a very specific isolated readback crash into WARN only when the
            // grant path already proved usable. It is a defense signal, not a generic binder failure.
            // 只有在 grant 路径已证明可用时，这个 matcher 才把特定的 isolated 回读崩溃提升为 WARN；它是防御信号，不是泛化的 binder 失败。
            val payload = stackPayload
                .replace("\r\n", "\n")
                .trim()
            if (payload.isBlank()) {
                return false
            }
            return payload.contains("No legacy keys for key descriptor") &&
                payload.contains("Error::Rc(r#KEY_NOT_FOUND) (code 7)") &&
                payload.contains("Caused by: android.os.ServiceSpecificException") &&
                payload.contains("while trying to load key info.")
        }

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
            privateResult: GrantDomainFullChainSplitResult = GrantDomainFullChainSplitResult(),
        ): GrantDomainFullChainSplitResult {
            // Keep the strongest signal, but preserve all stage summaries so a clean Java pass does
            // not hide a lower-level isolated APP/GRANT split found by private Binder.
            // 保留最强信号，同时保留所有阶段摘要，避免 Java 绿卡掩盖 private Binder 发现的 isolated APP/GRANT 断裂。
            val selected = when {
                privateResult.isDanger() -> privateResult
                hiddenResult.isDanger() -> hiddenResult
                publicResult.isDanger() -> publicResult
                privateResult.anomalyKind == GrantDomainAnomalyKind.ISOLATED_PRIVATE_READBACK_CRASH -> privateResult
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
    ISOLATED_PRIVATE_READBACK_CRASH,
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
