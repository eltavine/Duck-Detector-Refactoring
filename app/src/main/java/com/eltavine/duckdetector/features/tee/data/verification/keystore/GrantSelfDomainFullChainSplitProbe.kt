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
) {

    private val appContext = context.applicationContext

    suspend fun inspect(useStrongBox: Boolean): GrantSelfDomainFullChainSplitResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.BAKLAVA) {
            return GrantSelfDomainFullChainSplitResult(
                detail = "Grant self-domain full-chain split probe requires Android 16 or newer.",
            )
        }
        val keyStoreManager = runCatching {
            appContext.getSystemService(KeyStoreManager::class.java)
        }.getOrNull() ?: return GrantSelfDomainFullChainSplitResult(
            detail = "KeyStoreManager grant API was unavailable.",
        )
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duck_grant_self_domain_${System.nanoTime()}"
        val selfUid = Process.myUid()
        var grantCreated = false
        return try {
            val ownerCertificates = runCatching {
                AndroidKeyStoreTools.generateAttestedEcChain(
                    keyStore = keyStore,
                    alias = alias,
                    challenge = "duck_grant_self_domain_${System.nanoTime()}".toByteArray(StandardCharsets.UTF_8),
                    useStrongBox = useStrongBox,
                )
            }.getOrElse { throwable ->
                return GrantSelfDomainFullChainSplitResult(
                    detail = "Owner attested key generation failed: ${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}",
                )
            }
            val ownerChain = GrantDomainCertificateChain.fromCertificates(ownerCertificates)
            if (ownerChain.certificates.isEmpty()) {
                return GrantSelfDomainFullChainSplitResult(
                    detail = "Owner KeyStore certificate chain was empty.",
                )
            }
            val grantId = runCatching {
                keyStoreManager.grantKeyAccess(alias, selfUid)
            }.getOrElse { throwable ->
                // owner 可见 alias 却被 grant path 报 key-not-found，说明 framework 叙事和 Keystore2 授权域发生断裂。
                // If owner sees the alias but the grant path reports key-not-found, framework narrative and Keystore2 grant state diverged.
                val anomalyKind = if (GrantDomainFullChainSplitProbe.isGrantAliasNotFound(throwable)) {
                    GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN
                } else {
                    GrantSelfDomainAnomalyKind.UNAVAILABLE
                }
                return GrantSelfDomainFullChainSplitResult(
                    executed = anomalyKind == GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
                    ownerChainLength = ownerChain.certificates.size,
                    anomalyKind = anomalyKind,
                    detail = "self grantKeyAccess failed: ${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}",
                )
            }
            grantCreated = true
            val grantCertificates = runCatching {
                keyStoreManager.getGrantedCertificateChainFromId(grantId)
                    .filterIsInstance<X509Certificate>()
            }.getOrElse { throwable ->
                return GrantSelfDomainFullChainSplitResult(
                    ownerChainLength = ownerChain.certificates.size,
                    grantIdPresent = true,
                    detail = "self getGrantedCertificateChainFromId failed: ${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}",
                )
            }
            val grantChain = GrantDomainCertificateChain.fromCertificates(grantCertificates)
            if (grantChain.certificates.isEmpty()) {
                return GrantSelfDomainFullChainSplitResult(
                    ownerChainLength = ownerChain.certificates.size,
                    grantChainLength = 0,
                    grantIdPresent = true,
                    detail = "Self Domain.GRANT certificate chain was empty.",
                )
            }
            // 同 UID 自授权验证普通 app 域能访问 Domain.GRANT；该路径避开 isolated_app 的 keystore2 SELinux 限制。
            // Self-grant verifies ordinary-app Domain.GRANT visibility while avoiding isolated_app keystore2 SELinux limits.
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
                detail = comparison.detail,
            )
        } catch (throwable: Throwable) {
            GrantSelfDomainFullChainSplitResult(
                detail = "Grant self-domain full-chain split probe failed: ${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}",
            )
        } finally {
            if (grantCreated) {
                runCatching { keyStoreManager.revokeKeyAccess(alias, selfUid) }
            }
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }

    companion object {
        internal fun compareChains(
            ownerChain: GrantDomainCertificateChain,
            grantChain: GrantDomainCertificateChain,
        ): GrantDomainFullChainComparison {
            return GrantDomainFullChainSplitProbe.compareChains(ownerChain, grantChain)
        }
    }
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
)

enum class GrantSelfDomainAnomalyKind {
    NONE,
    SELF_CHAIN_SPLIT,
    SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
    UNAVAILABLE,
}
