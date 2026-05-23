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
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.security.MessageDigest
import java.security.UnrecoverableKeyException
import java.security.cert.X509Certificate
import java.nio.charset.StandardCharsets
import java.util.Locale

class GrantDomainFullChainSplitProbe(
    context: Context,
    private val granteeManager: TeeGrantDomainGranteeManager = TeeGrantDomainGranteeManager(context),
    private val privateGrantClient: Keystore2PrivateGrantClient = Keystore2PrivateGrantClient(),
) {

    suspend fun inspect(useStrongBox: Boolean): GrantDomainFullChainSplitResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return GrantDomainFullChainSplitResult(
                detail = "Grant-domain private binder probe requires Android 12 or newer.",
            )
        }
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duck_grant_domain_${System.nanoTime()}"
        var granteeUid: Int? = null
        var grantCreated = false
        var result = GrantDomainFullChainSplitResult()
        var keystore2Binder: IBinder? = null
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
                result = GrantDomainFullChainSplitResult(
                    detail = "Owner attested key generation failed: ${describeThrowable(generationFailure)}",
                )
            } else {
                keystore2Binder = privateGrantClient.lookupBinder()
                if (keystore2Binder == null) {
                    result = GrantDomainFullChainSplitResult(
                        detail = "private keystore2 binder unavailable.",
                    )
                } else {
                    val ownerChainResult = privateGrantClient.readOwnerChain(alias)
                    if (!ownerChainResult.available) {
                        result = GrantDomainFullChainSplitResult(
                            detail = ownerChainResult.detail.ifBlank { "private getKeyEntry(APP) owner chain unavailable." },
                        )
                    } else {
                        val ownerChain = ownerChainResult.chain
                        if (ownerChain.certificates.isEmpty()) {
                            result = GrantDomainFullChainSplitResult(
                                detail = "private getKeyEntry(APP) owner chain was empty.",
                            )
                        } else {
                            // isolated-domain 特意跨 UID / process 验证 Domain.GRANT；grantee 侧不可达可能只是 SELinux/app_zygote 策略噪声。
                            // isolated-domain intentionally crosses UID/process boundaries; grantee failures can reflect SELinux/app_zygote policy noise.
                            val sessionResult = granteeManager.openSession()
                            if (!sessionResult.available || sessionResult.session == null) {
                                result = GrantDomainFullChainSplitResult(
                                    detail = sessionResult.detail.ifBlank { "Isolated grant-domain grantee was unavailable." },
                                )
                            } else {
                                sessionResult.session.use { session ->
                                    granteeUid = session.uid
                                    val grantResult = privateGrantClient.grantAliasToUid(alias, session.uid)
                                    if (!grantResult.available || grantResult.grantId == null) {
                                        // 这里 owner 已通过私有 getKeyEntry(APP) 读到 alias 的真实证书链；AOSP grant path 应能解析同一 alias 再创建 Domain.GRANT。
                                        // Owner has already read a concrete chain through private getKeyEntry(APP); AOSP grant path should resolve the same alias before creating Domain.GRANT.
                                        // key-not-found 因此表示 owner 视图和 keystore2 授权查找断裂，而不是普通 isolated service 兼容性失败。
                                        // key-not-found therefore means owner visibility and keystore2 grant lookup diverged, not a generic isolated-service failure.
                                        val anomalyKind = if (grantResult.errorKind == Keystore2PrivateGrantErrorKind.KEY_NOT_FOUND) {
                                            GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN
                                        } else {
                                            GrantDomainAnomalyKind.UNAVAILABLE
                                        }
                                        result = GrantDomainFullChainSplitResult(
                                            executed = anomalyKind == GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
                                            ownerChainLength = ownerChain.certificates.size,
                                            granteeUid = session.uid,
                                            anomalyKind = anomalyKind,
                                            detail = grantResult.detail.ifBlank { "private isolated grant failed." },
                                        )
                                    } else {
                                        val grantId = grantResult.grantId
                                        grantCreated = true
                                        val granteeResult = session.readGrantedCertificateChain(grantId, keystore2Binder)
                                        // grant 创建后的 grantee 读取失败保持 INFO：isolated_app 访问 keystore2 的策略差异不是证书叙事 split 证据。
                                        // After grant creation, grantee read failures stay INFO: isolated_app keystore2 access policy is not certificate narrative split evidence.
                                        result = if (!granteeResult.available) {
                                            GrantDomainFullChainSplitResult(
                                                ownerChainLength = ownerChain.certificates.size,
                                                granteeUid = session.uid,
                                                detail = granteeResult.detail.ifBlank {
                                                    "isolated private binder readback blocked."
                                                },
                                            )
                                        } else {
                                            val granteeChain = granteeResult.chain
                                            if (granteeChain.certificates.isEmpty()) {
                                                GrantDomainFullChainSplitResult(
                                                    ownerChainLength = ownerChain.certificates.size,
                                                    granteeChainLength = 0,
                                                    granteeUid = session.uid,
                                                    detail = "Isolated private Domain.GRANT certificate chain was empty.",
                                                )
                                            } else {
                                                // 比较 ordered full-chain，而不是只看 leaf；部分 hook 可能只替换叶证书或只回放中间链。
                                                // Compare the ordered full chain, not only the leaf; hooks may rewrite only the leaf or replay only intermediates.
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
                                                    detail = comparison.detail,
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (throwable: Throwable) {
            result = GrantDomainFullChainSplitResult(
                detail = "Grant-domain full-chain split probe failed: ${describeThrowable(throwable)}",
            )
        } finally {
            granteeUid?.takeIf { grantCreated }?.let { uid ->
                val cleanupResult = privateGrantClient.revokeAliasGrant(alias, uid)
                if (!cleanupResult.available) {
                    result = result.copy(
                        detail = appendDetail(
                            result.detail,
                            cleanupResult.detail.ifBlank { "private ungrant failed." },
                        ),
                    )
                }
            }
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
        return result
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
            val type = throwable.javaClass.simpleName.ifBlank { throwable.javaClass.name }
            val message = throwable.message?.takeIf { it.isNotBlank() }
            return if (message == null) type else "$type: $message"
        }

        internal fun isGrantAliasNotFound(throwable: Throwable): Boolean {
            // 严格限定异常类型和 AOSP 文案，避免把 OEM/暂态 grant 失败误归因为授权域断裂。
            // Keep both exception type and AOSP-style message strict to avoid treating OEM/transient grant failures as domain divergence.
            return throwable is UnrecoverableKeyException &&
                throwable.message?.contains("No key found by the given alias", ignoreCase = true) == true
        }

        internal fun appendDetail(detail: String, extra: String): String {
            return GrantSelfDomainFullChainSplitProbe.appendDetail(detail, extra)
        }
    }
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
