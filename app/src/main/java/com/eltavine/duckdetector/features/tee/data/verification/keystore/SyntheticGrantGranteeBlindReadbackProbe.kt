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

class SyntheticGrantGranteeBlindReadbackProbe(
    context: Context,
    private val granteeManager: TeeGrantDomainGranteeManager = TeeGrantDomainGranteeManager(context),
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
    private val privateGrantClient: Keystore2PrivateGrantClient = Keystore2PrivateGrantClient(),
) {

    suspend fun inspect(useStrongBox: Boolean): SyntheticGrantGranteeBlindReadbackResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return SyntheticGrantGranteeBlindReadbackResult(
                detail = "Grant caller-binding private binder probe requires Android 12 or newer.",
            )
        }
        val alias = "duck_grant_binding_${System.nanoTime()}"
        val diagnostics = GrantDetectionDiagnosticLog(
            title = "Grant caller-binding diagnostic alias=$alias",
        )
        val granteeResult = granteeManager.openSession()
        if (!granteeResult.available || granteeResult.session == null) {
            diagnostics.add("isolated-session", granteeResult.detail)
            return SyntheticGrantGranteeBlindReadbackResult(
                detail = "Private: isolated grantee unavailable.",
                diagnosticCopyText = diagnostics.text(),
            )
        }

        return granteeResult.session.use { granteeSession ->
            val privateSessionResult = binderClient.openSession(useStrongBox = useStrongBox)
            val privateSession = privateSessionResult.session ?: return@use SyntheticGrantGranteeBlindReadbackResult(
                granteeUid = granteeSession.uid,
                detail = privateSessionResult.failureReason
                    ?: "Private: owner Keystore2 binder session unavailable.",
                diagnosticCopyText = diagnostics.text(),
            )
            val requestedDescriptor = binderClient.createKeyDescriptor(alias)
            var followUpDescriptor: Any = requestedDescriptor
            var grantCreated = false
            var result = SyntheticGrantGranteeBlindReadbackResult(
                granteeUid = granteeSession.uid,
                detail = "Private: grant caller-binding probe did not complete.",
            )
            try {
                result = run privateCycle@{
                    val generated = runCatching {
                        binderClient.generateSigningKey(
                            securityLevel = privateSession.securityLevel,
                            keyDescriptor = requestedDescriptor,
                            attestationKeyDescriptor = null,
                            attest = true,
                        )
                    }.getOrElse { throwable ->
                        diagnostics.addThrowable("private-generate", throwable)
                        return@privateCycle SyntheticGrantGranteeBlindReadbackResult(
                            granteeUid = granteeSession.uid,
                            detail = "Private: owner key generation failed (${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}).",
                        )
                    }
                    followUpDescriptor = binderClient.resolveFollowUpDescriptor(requestedDescriptor, generated)

                    val ownerResult = privateGrantClient.readOwnerChain(privateSession.service, alias)
                    ownerResult.throwable?.let { diagnostics.addThrowable("private-owner-chain", it) }
                    if (!ownerResult.available) {
                        return@privateCycle SyntheticGrantGranteeBlindReadbackResult(
                            granteeUid = granteeSession.uid,
                            detail = ownerResult.detail,
                        )
                    }

                    val grantResult = privateGrantClient.grantAliasToUid(
                        service = privateSession.service,
                        alias = alias,
                        uid = granteeSession.uid,
                    )
                    grantResult.throwable?.let { diagnostics.addThrowable("private-grant", it) }
                    val grantId = grantResult.grantId
                    if (!grantResult.available || grantId == null) {
                        return@privateCycle SyntheticGrantGranteeBlindReadbackResult(
                            granteeUid = granteeSession.uid,
                            detail = grantResult.detail,
                        )
                    }
                    grantCreated = true

                    val allowedRead = granteeSession.readGrantedCertificateChain(grantId, privateSession.binder)
                    allowedRead.diagnosticCopyText.takeIf { it.isNotBlank() }?.let(diagnostics::addRaw)
                    if (!allowedRead.available) {
                        return@privateCycle SyntheticGrantGranteeBlindReadbackResult(
                            executed = true,
                            grantCreated = true,
                            granteeUid = granteeSession.uid,
                            detail = "Private: grantee readback unavailable (${visibleGrantDetail(allowedRead.detail)}).",
                        )
                    }

                    val ownerReplay = privateGrantClient.readGrantEntry(privateSession.service, grantId)
                    ownerReplay.throwable?.let { diagnostics.addThrowable("private-owner-replay", it) }
                    evaluateOwnerReplay(
                        granteeUid = granteeSession.uid,
                        ownerReplay = ownerReplay,
                    )
                }
            } catch (throwable: Throwable) {
                diagnostics.addThrowable("probe-failure", throwable)
                result = SyntheticGrantGranteeBlindReadbackResult(
                    executed = grantCreated,
                    grantCreated = grantCreated,
                    granteeUid = granteeSession.uid,
                    detail = "Grant caller-binding private binder probe failed: ${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}",
                )
            } finally {
                if (grantCreated) {
                    val revoke = privateGrantClient.revokeAliasGrant(
                        service = privateSession.service,
                        alias = alias,
                        uid = granteeSession.uid,
                    )
                    revoke.throwable?.let { diagnostics.addThrowable("private-revoke", it) }
                    if (!revoke.available) {
                        result = result.copy(
                            detail = appendGrantDetail(result.detail, revoke.detail),
                        )
                    }
                }
                binderClient.deleteKeyChecked(privateSession.service, followUpDescriptor)?.let { throwable ->
                    diagnostics.addThrowable("private-delete", throwable)
                    result = result.copy(
                        detail = appendGrantDetail(
                            result.detail,
                            "Private cleanup deleteKey failed (${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}).",
                        ),
                    )
                }
                binderClient.closeSession(privateSession)
            }
            result.copy(diagnosticCopyText = diagnostics.text())
        }
    }

    companion object {
        fun skippedAfterExistingGrantDanger(): SyntheticGrantGranteeBlindReadbackResult {
            return SyntheticGrantGranteeBlindReadbackResult(
                anomalyKind = SyntheticGrantGranteeBlindReadbackAnomalyKind.SKIPPED_AFTER_EXISTING_GRANT_DANGER,
                detail = "Skipped because an existing grant detector already reported danger.",
            )
        }

        internal fun evaluateOwnerReplay(
            granteeUid: Int,
            ownerReplay: Keystore2PrivateGrantResult,
        ): SyntheticGrantGranteeBlindReadbackResult {
            return when {
                ownerReplay.available -> SyntheticGrantGranteeBlindReadbackResult(
                    executed = true,
                    available = true,
                    grantCreated = true,
                    granteeUid = granteeUid,
                    granteeReadSucceeded = true,
                    ownerReplaySucceeded = true,
                    ownerReplayErrorKind = Keystore2PrivateGrantErrorKind.NONE,
                    anomalyKind = SyntheticGrantGranteeBlindReadbackAnomalyKind.NON_GRANTEE_READBACK_ALLOWED,
                    detail = "Private: non-grantee owner replay succeeded for isolated grant handle.",
                )
                ownerReplay.errorKind == Keystore2PrivateGrantErrorKind.KEY_NOT_FOUND ->
                    SyntheticGrantGranteeBlindReadbackResult(
                        executed = true,
                        available = true,
                        grantCreated = true,
                        granteeUid = granteeUid,
                        granteeReadSucceeded = true,
                        ownerReplayErrorKind = ownerReplay.errorKind,
                        anomalyKind = SyntheticGrantGranteeBlindReadbackAnomalyKind.NONE,
                        detail = "Private: owner replay rejected with KEY_NOT_FOUND.",
                    )
                else -> SyntheticGrantGranteeBlindReadbackResult(
                    executed = true,
                    grantCreated = true,
                    granteeUid = granteeUid,
                    granteeReadSucceeded = true,
                    ownerReplayErrorKind = ownerReplay.errorKind,
                    detail = "Private: owner replay unavailable (${ownerReplay.detail}).",
                )
            }
        }
    }
}

data class SyntheticGrantGranteeBlindReadbackResult(
    val executed: Boolean = false,
    val available: Boolean = false,
    val grantCreated: Boolean = false,
    val granteeUid: Int? = null,
    val granteeReadSucceeded: Boolean = false,
    val ownerReplaySucceeded: Boolean = false,
    val ownerReplayErrorKind: Keystore2PrivateGrantErrorKind? = null,
    val anomalyKind: SyntheticGrantGranteeBlindReadbackAnomalyKind =
        SyntheticGrantGranteeBlindReadbackAnomalyKind.UNAVAILABLE,
    val detail: String = "",
    val diagnosticCopyText: String = "",
)

enum class SyntheticGrantGranteeBlindReadbackAnomalyKind {
    NONE,
    NON_GRANTEE_READBACK_ALLOWED,
    SKIPPED_AFTER_EXISTING_GRANT_DANGER,
    UNAVAILABLE,
}
