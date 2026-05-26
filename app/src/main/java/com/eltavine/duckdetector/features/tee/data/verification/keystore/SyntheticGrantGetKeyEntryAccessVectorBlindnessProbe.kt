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

class SyntheticGrantGetKeyEntryAccessVectorBlindnessProbe(
    context: Context,
    private val granteeManager: TeeGrantDomainGranteeManager = TeeGrantDomainGranteeManager(context),
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
    private val privateGrantClient: Keystore2PrivateGrantClient = Keystore2PrivateGrantClient(),
) {

    suspend fun inspect(useStrongBox: Boolean): SyntheticGrantGetKeyEntryAccessVectorBlindnessResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                detail = "Grant access-vector private binder probe requires Android 12 or newer.",
            )
        }
        val alias = "duck_grant_access_vector_${System.nanoTime()}"
        val diagnostics = GrantDetectionDiagnosticLog(
            title = "Grant access-vector diagnostic alias=$alias",
        )
        val granteeResult = granteeManager.openSession()
        if (!granteeResult.available || granteeResult.session == null) {
            diagnostics.add("isolated-session", granteeResult.detail)
            return SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                detail = "Private: isolated grantee unavailable.",
                diagnosticCopyText = diagnostics.text(),
            )
        }

        return granteeResult.session.use { granteeSession ->
            val privateSessionResult = binderClient.openSession(useStrongBox = useStrongBox)
            val privateSession = privateSessionResult.session ?: return@use SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                granteeUid = granteeSession.uid,
                detail = privateSessionResult.failureReason
                    ?: "Private: owner Keystore2 binder session unavailable.",
                diagnosticCopyText = diagnostics.text(),
            )
            val requestedDescriptor = binderClient.createKeyDescriptor(alias)
            var followUpDescriptor: Any = requestedDescriptor
            var grantCreated = false
            var result = SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                granteeUid = granteeSession.uid,
                detail = "Private: grant access-vector probe did not complete.",
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
                        return@privateCycle SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                            granteeUid = granteeSession.uid,
                            detail = "Private: owner key generation failed (${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}).",
                        )
                    }
                    followUpDescriptor = binderClient.resolveFollowUpDescriptor(requestedDescriptor, generated)

                    val ownerResult = privateGrantClient.readOwnerChain(privateSession.service, alias)
                    ownerResult.throwable?.let { diagnostics.addThrowable("private-owner-chain", it) }
                    if (!ownerResult.available) {
                        return@privateCycle SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                            granteeUid = granteeSession.uid,
                            detail = ownerResult.detail,
                        )
                    }

                    val accessVector = privateGrantClient.constantsSnapshot().permissionUse
                    val grantResult = privateGrantClient.grantAliasToUid(
                        service = privateSession.service,
                        alias = alias,
                        uid = granteeSession.uid,
                        accessVector = accessVector,
                    )
                    grantResult.throwable?.let { diagnostics.addThrowable("private-grant-use-only", it) }
                    val grantId = grantResult.grantId
                    if (!grantResult.available || grantId == null) {
                        return@privateCycle SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                            granteeUid = granteeSession.uid,
                            accessVector = accessVector,
                            detail = grantResult.detail,
                        )
                    }
                    grantCreated = true

                    val granteeRead = granteeSession.readGrantedCertificateChain(grantId, privateSession.binder)
                    granteeRead.diagnosticCopyText.takeIf { it.isNotBlank() }?.let(diagnostics::addRaw)
                    evaluateGranteeReadback(
                        granteeUid = granteeSession.uid,
                        accessVector = accessVector,
                        granteeRead = granteeRead,
                    )
                }
            } catch (throwable: Throwable) {
                diagnostics.addThrowable("probe-failure", throwable)
                result = SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                    executed = grantCreated,
                    grantCreated = grantCreated,
                    granteeUid = granteeSession.uid,
                    detail = "Grant access-vector private binder probe failed: ${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}",
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
        fun skippedAfterExistingGrantDanger(): SyntheticGrantGetKeyEntryAccessVectorBlindnessResult {
            return SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                anomalyKind = SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.SKIPPED_AFTER_EXISTING_GRANT_DANGER,
                detail = "Skipped because an existing grant detector already reported danger.",
            )
        }

        internal fun evaluateGranteeReadback(
            granteeUid: Int,
            accessVector: Int,
            granteeRead: TeeGrantDomainGranteeChainResult,
        ): SyntheticGrantGetKeyEntryAccessVectorBlindnessResult {
            return when {
                granteeRead.available -> SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                    executed = true,
                    available = true,
                    grantCreated = true,
                    granteeUid = granteeUid,
                    accessVector = accessVector,
                    granteeReadSucceeded = true,
                    granteeReadErrorKind = Keystore2PrivateGrantErrorKind.NONE,
                    anomalyKind = SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.GET_KEY_ENTRY_WITHOUT_GET_INFO_ALLOWED,
                    detail = "Private: grantee getKeyEntry(GRANT) succeeded without GET_INFO.",
                )
                granteeRead.errorKind == Keystore2PrivateGrantErrorKind.PERMISSION_DENIED ->
                    SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                        executed = true,
                        available = true,
                        grantCreated = true,
                        granteeUid = granteeUid,
                        accessVector = accessVector,
                        granteeReadErrorKind = granteeRead.errorKind,
                        anomalyKind = SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.NONE,
                        detail = "Private: grantee getKeyEntry(GRANT) rejected with PERMISSION_DENIED.",
                    )
                else -> SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                    executed = true,
                    grantCreated = true,
                    granteeUid = granteeUid,
                    accessVector = accessVector,
                    granteeReadErrorKind = granteeRead.errorKind,
                    detail = "Private: grantee readback unavailable (${visibleGrantDetail(granteeRead.detail)}).",
                )
            }
        }
    }
}

data class SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
    val executed: Boolean = false,
    val available: Boolean = false,
    val grantCreated: Boolean = false,
    val granteeUid: Int? = null,
    val accessVector: Int? = null,
    val granteeReadSucceeded: Boolean = false,
    val granteeReadErrorKind: Keystore2PrivateGrantErrorKind? = null,
    val anomalyKind: SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind =
        SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.UNAVAILABLE,
    val detail: String = "",
    val diagnosticCopyText: String = "",
)

enum class SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind {
    NONE,
    GET_KEY_ENTRY_WITHOUT_GET_INFO_ALLOWED,
    SKIPPED_AFTER_EXISTING_GRANT_DANGER,
    UNAVAILABLE,
}
