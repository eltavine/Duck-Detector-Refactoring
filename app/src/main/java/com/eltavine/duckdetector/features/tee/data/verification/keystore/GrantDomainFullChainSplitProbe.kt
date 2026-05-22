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
import android.security.keystore.KeyStoreManager
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.security.MessageDigest
import java.security.UnrecoverableKeyException
import java.security.cert.X509Certificate
import java.nio.charset.StandardCharsets
import java.util.Locale

class GrantDomainFullChainSplitProbe(
    context: Context,
    private val granteeManager: TeeGrantDomainGranteeManager = TeeGrantDomainGranteeManager(context),
) {

    private val appContext = context.applicationContext

    suspend fun inspect(useStrongBox: Boolean): GrantDomainFullChainSplitResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.BAKLAVA) {
            return GrantDomainFullChainSplitResult(
                detail = "Grant-domain full-chain split probe requires Android 16 or newer.",
            )
        }
        val keyStoreManager = runCatching {
            appContext.getSystemService(KeyStoreManager::class.java)
        }.getOrNull() ?: return GrantDomainFullChainSplitResult(
            detail = "KeyStoreManager grant API was unavailable.",
        )
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duck_grant_domain_${System.nanoTime()}"
        var granteeUid: Int? = null
        var grantCreated = false
        return try {
            val ownerCertificates = runCatching {
                AndroidKeyStoreTools.generateAttestedEcChain(
                    keyStore = keyStore,
                    alias = alias,
                    challenge = "duck_grant_domain_${System.nanoTime()}".toByteArray(StandardCharsets.UTF_8),
                    useStrongBox = useStrongBox,
                )
            }.getOrElse { throwable ->
                return GrantDomainFullChainSplitResult(
                    detail = "Owner attested key generation failed: ${describeThrowable(throwable)}",
                )
            }
            val ownerChain = GrantDomainCertificateChain.fromCertificates(ownerCertificates)
            if (ownerChain.certificates.isEmpty()) {
                return GrantDomainFullChainSplitResult(
                    detail = "Owner KeyStore certificate chain was empty.",
                )
            }
            // isolated-domain 特意跨 UID / process 验证 Domain.GRANT；grantee 侧不可达可能只是 SELinux/app_zygote 策略噪声。
            // isolated-domain intentionally crosses UID/process boundaries; grantee failures can reflect SELinux/app_zygote policy noise.
            val sessionResult = granteeManager.openSession()
            if (!sessionResult.available || sessionResult.session == null) {
                return GrantDomainFullChainSplitResult(
                    detail = sessionResult.detail.ifBlank { "Isolated grant-domain grantee was unavailable." },
                )
            }
            sessionResult.session.use { session ->
                granteeUid = session.uid
                val grantId = runCatching {
                    keyStoreManager.grantKeyAccess(alias, session.uid)
                }.getOrElse { throwable ->
                    // 这里 owner 已通过 Java KeyStore 读到 alias 的真实证书链；AOSP grant path 应能解析同一 alias 再创建 Domain.GRANT。
                    // Owner has already read a concrete chain for alias; AOSP grant path should resolve the same alias before creating Domain.GRANT.
                    // key-not-found 因此表示 owner 视图和 keystore2 授权查找断裂，而不是普通 isolated service 兼容性失败。
                    // key-not-found therefore means owner visibility and keystore2 grant lookup diverged, not a generic isolated-service failure.
                    val anomalyKind = if (isGrantAliasNotFound(throwable)) {
                        GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN
                    } else {
                        GrantDomainAnomalyKind.UNAVAILABLE
                    }
                    return GrantDomainFullChainSplitResult(
                        executed = anomalyKind == GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
                        ownerChainLength = ownerChain.certificates.size,
                        granteeUid = session.uid,
                        anomalyKind = anomalyKind,
                        detail = "grantKeyAccess failed: ${describeThrowable(throwable)}",
                    )
                }
                grantCreated = true
                val granteeResult = session.readGrantedCertificateChain(grantId)
                // grant 创建后的 grantee 读取失败保持 INFO：isolated_app 访问 keystore2 的策略差异不是证书叙事 split 证据。
                // After grant creation, grantee read failures stay INFO: isolated_app keystore2 access policy is not certificate narrative split evidence.
                if (!granteeResult.available) {
                    return GrantDomainFullChainSplitResult(
                        ownerChainLength = ownerChain.certificates.size,
                        granteeUid = session.uid,
                        detail = granteeResult.detail.ifBlank {
                            "Grantee getGrantedCertificateChainFromId() was unavailable."
                        },
                    )
                }
                val granteeChain = granteeResult.chain
                if (granteeChain.certificates.isEmpty()) {
                    return GrantDomainFullChainSplitResult(
                        ownerChainLength = ownerChain.certificates.size,
                        granteeChainLength = 0,
                        granteeUid = session.uid,
                        detail = "Grantee granted certificate chain was empty.",
                    )
                }
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
        } catch (throwable: Throwable) {
            GrantDomainFullChainSplitResult(
                detail = "Grant-domain full-chain split probe failed: ${describeThrowable(throwable)}",
            )
        } finally {
            granteeUid?.takeIf { grantCreated }?.let { uid ->
                runCatching { keyStoreManager.revokeKeyAccess(alias, uid) }
            }
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
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
