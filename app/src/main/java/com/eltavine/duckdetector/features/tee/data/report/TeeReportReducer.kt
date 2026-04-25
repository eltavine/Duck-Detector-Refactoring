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

package com.eltavine.duckdetector.features.tee.data.report

import android.os.Build
import com.eltavine.duckdetector.features.tee.data.attestation.AttestationSnapshot
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceItem
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceSection
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkMode
import com.eltavine.duckdetector.features.tee.domain.TeePatchGrade
import com.eltavine.duckdetector.features.tee.domain.TeePatchState
import com.eltavine.duckdetector.features.tee.domain.TeeReport
import com.eltavine.duckdetector.features.tee.domain.TeeScanStage
import com.eltavine.duckdetector.features.tee.domain.TeeSignal
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import com.eltavine.duckdetector.features.tee.domain.TeeTrustRoot
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TIMING_SIDE_CHANNEL_THRESHOLD_MILLIS
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingSideChannelResult
import java.time.LocalDate
import java.time.Period
import java.util.Locale
import kotlin.math.absoluteValue

class TeeReportReducer(
    private val exportFormatter: TeeExportFormatter = TeeExportFormatter(),
) {

    private enum class GenerateModeAnomalyState {
        MATCHED,
        CLEAN,
        UNAVAILABLE,
    }

    private enum class TimingSideChannelSkipSignature(
        val summary: String,
        val rowLabel: String,
        val level: TeeSignalLevel,
    ) {
        // 这些标签只在“测量未建立”的 skip 语义里生效，用来把静态栈特征提升成可见的 patch-mode 结论。
        // These labels only apply to skip semantics where measurement never started, promoting static stack signatures into visible patch-mode outcomes.
        TRICKY_STORE_PATCH_MODE(
            // 用户可见文案统一收敛成“恶意模块指纹”，避免把具体模块/模式名暴露给最终展示层。
            // User-visible wording is intentionally collapsed into a generic malicious-module fingerprint message so the UI does not expose vendor/module-specific labels.
            summary = "Detected malicious-module fingerprint during timing skip.",
            rowLabel = "Detected malicious-module fingerprint",
            level = TeeSignalLevel.FAIL,
        ),
        TEE_SIMULATOR_PATCH_MODE(
            summary = "Detected malicious-module fingerprint during timing skip.",
            rowLabel = "Detected malicious-module fingerprint",
            level = TeeSignalLevel.FAIL,
        ),
        PRIVATE_BINDER_EXCEPTION(
            summary = "Captured private binder exception during timing skip.",
            rowLabel = "Captured private binder exception during timing skip",
            level = TeeSignalLevel.WARN,
        ),
    }

    fun reduce(artifacts: TeeScanArtifacts): TeeReport {
        val patchState = buildPatchState(artifacts)
        val policyHardIndicators = collectPolicyHardIndicators(artifacts)
        val policySoftIndicators = collectPolicySoftIndicators(artifacts, patchState)
        val supplementaryIndicators = collectSupplementaryIndicators(artifacts)
        val effectiveTier = effectiveTier(artifacts)
        val verdict = determineVerdict(artifacts, policyHardIndicators, policySoftIndicators)
        val supplementaryDangerCount =
            supplementaryIndicators.count { it.level == TeeSignalLevel.FAIL }
        val supplementaryWarningCount =
            supplementaryIndicators.count { it.level == TeeSignalLevel.WARN }
        val tamperScore = (
                (policyHardIndicators.size * 28) +
                        (policySoftIndicators.size * 8) +
                        (supplementaryDangerCount * 10) +
                        (supplementaryWarningCount * 4)
                ).coerceAtMost(100)
        val sections = buildSections(
            artifacts = artifacts,
            patchState = patchState,
            policyHardIndicators = policyHardIndicators,
            policySoftIndicators = policySoftIndicators,
            supplementaryIndicators = supplementaryIndicators,
        )
        val normalizedTrustRoot = normalizeTrustRoot(artifacts.trust.trustRoot)
        val report = TeeReport(
            stage = TeeScanStage.READY,
            verdict = verdict,
            tier = effectiveTier,
            headline = headlineFor(verdict, supplementaryIndicators),
            summary = summaryFor(
                verdict = verdict,
                artifacts = artifacts,
                policyHardIndicators = policyHardIndicators,
                policySoftIndicators = policySoftIndicators,
                supplementaryIndicators = supplementaryIndicators,
            ),
            collapsedSummary = collapsedSummaryFor(
                verdict = verdict,
                policyHardIndicators = policyHardIndicators,
                policySoftIndicators = policySoftIndicators,
                supplementaryIndicators = supplementaryIndicators,
            ),
            trustRoot = normalizedTrustRoot,
            localTrustChainLevel = localTrustChainLevel(artifacts),
            trustSummary = trustSummaryFor(artifacts),
            tamperScore = tamperScore,
            evidenceCount = sections.sumOf { it.items.size },
            supplementaryIndicatorCount = supplementaryIndicators.size,
            supplementaryReviewLevel = supplementaryReviewLevel(supplementaryIndicators),
            signals = buildSignals(
                artifacts = artifacts,
                patchState = patchState,
                policyHardIndicators = policyHardIndicators,
                policySoftIndicators = policySoftIndicators,
                supplementaryIndicators = supplementaryIndicators,
            ),
            sections = sections,
            certificates = artifacts.snapshot.displayCertificates,
            rkpState = artifacts.rkp,
            patchState = patchState,
            soterState = artifacts.soter,
            networkState = artifacts.crl.networkState,
            exportText = "",
            failureMessage = artifacts.snapshot.errorMessage,
        )
        return report.copy(exportText = exportFormatter.format(report))
    }

    private fun determineVerdict(
        artifacts: TeeScanArtifacts,
        policyHardIndicators: List<TeeEvidenceItem>,
        policySoftIndicators: List<TeeEvidenceItem>,
    ): TeeVerdict {
        val tier = effectiveTier(artifacts)
        return when {
            policyHardIndicators.isNotEmpty() -> TeeVerdict.TAMPERED
            tier == TeeTier.NONE -> TeeVerdict.BROKEN
            tier == TeeTier.SOFTWARE -> TeeVerdict.BROKEN
            tier == TeeTier.UNKNOWN && artifacts.snapshot.rawCertificates.isEmpty() -> TeeVerdict.BROKEN
            policySoftIndicators.isNotEmpty() -> TeeVerdict.SUSPICIOUS
            tier == TeeTier.TEE || tier == TeeTier.STRONGBOX -> TeeVerdict.CONSISTENT
            else -> TeeVerdict.INCONCLUSIVE
        }
    }

    private fun collectPolicyHardIndicators(artifacts: TeeScanArtifacts): List<TeeEvidenceItem> {
        return buildList {
            if (!artifacts.trust.chainSignatureValid) {
                add(
                    fact(
                        "Chain signature",
                        "Certificate signatures did not verify locally.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.snapshot.trustedAttestationIndex != null && !artifacts.snapshot.challengeVerified) {
                add(
                    fact(
                        "Challenge",
                        "Attestation challenge did not match the local request.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.bootConsistency.vbmetaDigestMismatch) {
                add(
                    fact(
                        "Boot consistency",
                        "Attested verifiedBootHash did not match ro.boot.vbmeta.digest.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.bootConsistency.vbmetaDigestMissingWhileAttestedHashPresent) {
                add(
                    fact(
                        "Boot consistency",
                        "Attested verifiedBootHash was present, but ro.boot.vbmeta.digest was empty.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.bootConsistency.verifiedBootHashAllZeros) {
                add(
                    fact(
                        "Verified boot hash",
                        "Attested verifiedBootHash was all zeros.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.bootConsistency.verifiedBootKeyAllZeros) {
                add(
                    fact(
                        "Verified boot key",
                        "Attested verifiedBootKey was all zeros.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.crl.revokedCertificates.isNotEmpty()) {
                add(
                    fact(
                        "Revocation",
                        "Official revocation feed matched certificate serials from the chain.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.soter.damaged) {
                add(fact("Soter", artifacts.soter.summary, TeeSignalLevel.FAIL))
            }
        }
    }

    private fun collectSupplementaryIndicators(artifacts: TeeScanArtifacts): List<TeeEvidenceItem> {
        return buildList {
            if (artifacts.soter.abnormalEnvironment) {
                add(
                    fact(
                        "Soter environment",
                        artifacts.soter.summary,
                        TeeSignalLevel.WARN,
                    )
                )
            }
            val timingSideChannelSkipSignature = timingSideChannelSkipSignature(artifacts.timingSideChannel)
            if (timingSideChannelSkipSignature != null) {
                add(
                    fact(
                        "Timing side-channel",
                        timingSideChannelSkipSignature.summary,
                        timingSideChannelSkipSignature.level,
                    )
                )
            } else if (artifacts.timingSideChannel.measurementAvailable && artifacts.timingSideChannel.suspicious) {
                add(
                    fact(
                        "Timing side-channel",
                        timingSideChannelSummary(artifacts),
                        TeeSignalLevel.WARN,
                    )
                )
            }
            if (generateModeAnomalyState(artifacts) == GenerateModeAnomalyState.MATCHED) {
                add(
                    fact(
                        "TEE Simulator generate-mode fingerprint",
                        "Matched TEE Simulator generate-mode fingerprint.",
                        TeeSignalLevel.FAIL,
                    )
                )
            }
            if (artifacts.keystore2Hook.javaHookDetected) {
                add(
                    fact(
                        "Keystore2",
                        "Binder reply fingerprint matched a Java-hook style path.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.legacyKeystorePath.executed &&
                artifacts.legacyKeystorePath.legacyMaterialAvailable &&
                !artifacts.legacyKeystorePath.chainMatches
            ) {
                add(
                    fact(
                        "Legacy keystore",
                        "Legacy USRCERT_/CACERT_ path diverged from the Java KeyStore certificate chain.",
                        TeeSignalLevel.WARN
                    )
                )
            }
            if (artifacts.listEntriesConsistency.executed &&
                (artifacts.listEntriesConsistency.inconsistent || artifacts.listEntriesConsistency.badParcelableLikeCrash)
            ) {
                add(
                    fact(
                        "listEntries",
                        "containsAlias()/aliases() diverged or crashed with a BadParcelable-style path.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.listEntriesBatched.executed &&
                (artifacts.listEntriesBatched.cursorEchoed || artifacts.listEntriesBatched.expectedNextMissing)
            ) {
                add(
                    fact(
                        "listEntriesBatched",
                        "Keystore2 listEntriesBatched(startPastAlias) diverged from expected cursor semantics.",
                        if (artifacts.listEntriesBatched.cursorEchoed) TeeSignalLevel.FAIL else TeeSignalLevel.WARN
                    )
                )
            }
            if (artifacts.keyMetadataSemantics.executed &&
                (!artifacts.keyMetadataSemantics.usesKeyIdDomain || !artifacts.keyMetadataSemantics.aliasCleared)
            ) {
                add(
                    fact(
                        "Key metadata",
                        "Keystore2 metadata.key did not normalize to KEY_ID semantics.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.keyMetadataShape.executed &&
                (!artifacts.keyMetadataShape.modificationTimeValid || !artifacts.keyMetadataShape.hasOriginTag)
            ) {
                add(
                    fact(
                        "Key metadata",
                        "Keystore2 metadata omitted expected modification time or ORIGIN authorization tags.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.keyboxImport.executed && !artifacts.keyboxImport.markerPreserved) {
                add(
                    fact(
                        "Keybox import",
                        "Imported marker certificate came back rewritten.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (!artifacts.pairConsistency.keyMatchesCertificate) {
                add(
                    fact(
                        "Key pair",
                        "Leaf certificate key did not verify fresh local signatures.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.aesGcm.executed && !artifacts.aesGcm.roundTripSucceeded) {
                add(
                    fact(
                        "AES-GCM",
                        "AndroidKeyStore AES-GCM round-trip failed.",
                        TeeSignalLevel.FAIL,
                    )
                )
            }
            if (artifacts.aesGcm.executed && artifacts.aesGcm.insideSecureHardware == false) {
                add(
                    fact(
                        "AES-GCM",
                        "AndroidKeyStore AES-GCM key was software-backed instead of secure hardware.",
                        TeeSignalLevel.WARN,
                    )
                )
            }
            if (!artifacts.lifecycle.deleteRemovedAlias || !artifacts.lifecycle.regeneratedFreshMaterial) {
                add(
                    fact(
                        "Lifecycle",
                        "Delete/regenerate behavior contradicted a clean keystore path.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (!artifacts.pureCertificate.pureCertificateReturnsNullKey) {
                add(
                    fact(
                        "Pure certificate",
                        "getKey() returned a key object for a certificate-only entry.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.pureCertificateSecurityLevel.executed &&
                artifacts.pureCertificateSecurityLevel.securityLevelPresent
            ) {
                add(
                    fact(
                        "Pure certificate",
                        "Certificate-only entry exposed Keystore2 security-level metadata.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.operationErrorPath.executed &&
                (!artifacts.operationErrorPath.createOperationSucceeded ||
                    !artifacts.operationErrorPath.updateAadServiceSpecific ||
                    !artifacts.operationErrorPath.oversizedUpdateRejected ||
                    !artifacts.operationErrorPath.abortInvalidatedHandle)
            ) {
                add(
                    fact(
                        "Operation path",
                        "Keystore2 operation error handling diverged from native-style semantics.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.biometricIntegration.executed &&
                artifacts.biometricIntegration.strongBiometricAvailable &&
                (!artifacts.biometricIntegration.keyCreated || !artifacts.biometricIntegration.keyRetrieved)
            ) {
                add(
                    fact(
                        "Biometric TEE",
                        "Strong biometric was available, but user-auth-bound key creation or retrieval failed.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.binderHookBootstrap.executed && !artifacts.binderHookBootstrap.hookInstalled) {
                add(
                    fact(
                        "Binder hook",
                        "Binder hook bootstrap did not complete successfully.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.binderPatchMode.executed &&
                artifacts.binderPatchMode.hookInstalled &&
                (artifacts.binderPatchMode.leafDiffers || artifacts.binderPatchMode.chainDiffers)
            ) {
                add(
                    fact(
                        "Patch mode",
                        "generateKey and getKeyEntry returned different certificate materials.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.binderChainConsistency.executed &&
                (
                    !artifacts.binderChainConsistency.hookInstalled ||
                        artifacts.binderChainConsistency.suspiciousLeafIssuerSpki ||
                        !artifacts.binderChainConsistency.activeProbeSecondCycleSucceeded ||
                        !artifacts.binderChainConsistency.deleteEntryRemovedAlias ||
                        (artifacts.binderChainConsistency.binderMaterialAvailable &&
                            !artifacts.binderChainConsistency.chainMatches) ||
                        (artifacts.binderChainConsistency.generateMaterialAvailable &&
                            artifacts.binderChainConsistency.binderMaterialAvailable &&
                            (
                                !artifacts.binderChainConsistency.generateVsGetKeyEntryLeafMatches ||
                                    !artifacts.binderChainConsistency.generateVsGetKeyEntryChainMatches
                                ))
                    )
            ) {
                add(
                    fact(
                        "Binder chain",
                        if (!artifacts.binderChainConsistency.hookInstalled) {
                            "Binder capture hook bootstrap failed."
                        } else {
                            "Java KeyStore, generateKey, and getKeyEntry certificate materials diverged."
                        },
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.updateSubcomponent.keyNotFoundStyleFailure) {
                add(
                    fact(
                        "Update path",
                        "setKeyEntry() failed with a key-not-found style response.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.native.leafDerPrimaryDetected) {
                add(
                    fact(
                        "TS leaf DER",
                        "Primary TrickyStore DER fingerprint matched locally.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.native.gotHookDetected) {
                add(
                    fact(
                        "TrickyStore ioctl",
                        "libbinder ioctl GOT entry differed from libc.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.native.inlineHookDetected) {
                add(
                    fact(
                        "TrickyStore ioctl",
                        "ioctl prologue looked patched or redirected.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.native.honeypotDetected) {
                add(
                    fact(
                        "TrickyStore ioctl",
                        "Keystore-style binder honeypot triggered abnormal ioctl timing.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.native.trickyStoreDetected) {
                add(
                    fact(
                        "TrickyStore",
                        "Process-side indicators matched ${nativeMethodSummary(artifacts)}.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            artifacts.strongBox.hardFailures.forEach { message ->
                add(fact("StrongBox", message, TeeSignalLevel.WARN))
            }
        }
    }

    private fun collectPolicySoftIndicators(
        artifacts: TeeScanArtifacts,
        patchState: TeePatchState,
    ): List<TeeEvidenceItem> {
        return buildList {
            artifacts.snapshot.errorMessage?.takeIf { it.isNotBlank() }?.let { message ->
                add(fact("Collector", message, TeeSignalLevel.WARN))
            }
            artifacts.chainStructure.issuerMismatches.forEach { mismatch ->
                add(fact("Issuer path", mismatch, TeeSignalLevel.WARN))
            }
            artifacts.chainStructure.expiredCertificates.forEach { expired ->
                add(fact("Certificate validity", expired, TeeSignalLevel.WARN))
            }
            if (artifacts.chainStructure.provisioningConsistencyIssue) {
                add(
                    fact(
                        "Provisioning layout",
                        "Provisioning info was not adjacent to the trusted attestation certificate.",
                        TeeSignalLevel.WARN
                    )
                )
            }
            if (artifacts.oversizedChallenge.acceptedOversizedChallenge) {
                add(
                    fact(
                        "Oversized challenge",
                        "Attestation accepted oversized challenge sizes: ${artifacts.oversizedChallenge.acceptedSizesLabel()}.",
                        TeeSignalLevel.WARN
                    )
                )
            }
            artifacts.rkp.consistencyIssue?.let { issue ->
                add(fact("RKP consistency", issue, TeeSignalLevel.WARN))
            }
        }
    }

    private fun buildSignals(
        artifacts: TeeScanArtifacts,
        patchState: TeePatchState,
        policyHardIndicators: List<TeeEvidenceItem>,
        policySoftIndicators: List<TeeEvidenceItem>,
        supplementaryIndicators: List<TeeEvidenceItem>,
    ): List<TeeSignal> {
        return buildList {
            add(
                TeeSignal(
                    "Local chain",
                    if (artifacts.trust.chainSignatureValid) "Verified" else "Failed",
                    if (artifacts.trust.chainSignatureValid) TeeSignalLevel.PASS else TeeSignalLevel.FAIL
                )
            )
            add(TeeSignal("Boot", bootSignalValue(artifacts), bootSignalLevel(artifacts)))
            add(
                TeeSignal(
                    "Signals",
                    indicatorValue(
                        policyHardIndicators = policyHardIndicators,
                        policySoftIndicators = policySoftIndicators,
                        supplementaryIndicators = supplementaryIndicators,
                    ),
                    indicatorLevel(
                        policyHardIndicators = policyHardIndicators,
                        policySoftIndicators = policySoftIndicators,
                        supplementaryIndicators = supplementaryIndicators,
                    ),
                ),
            )
            if (generateModeAnomalyState(artifacts) == GenerateModeAnomalyState.MATCHED) {
                add(TeeSignal("TEE Simulator generate-mode fingerprint", "Matched", TeeSignalLevel.FAIL))
            }
            add(TeeSignal("CRL", crlSignalValue(artifacts), crlSignalLevel(artifacts)))
            if (artifacts.native.trickyStoreDetected || artifacts.native.leafDerPrimaryDetected || artifacts.native.leafDerSecondaryDetected) {
                add(TeeSignal("Native", nativeSignalValue(artifacts), nativeSignalLevel(artifacts)))
            }
            if (artifacts.keystore2Hook.available || artifacts.keystore2Hook.javaHookDetected) {
                add(
                    TeeSignal(
                        "Keystore2",
                        keystore2Value(artifacts),
                        if (artifacts.keystore2Hook.javaHookDetected) TeeSignalLevel.FAIL else TeeSignalLevel.INFO,
                    ),
                )
            }
        }
    }

    private fun buildSections(
        artifacts: TeeScanArtifacts,
        patchState: TeePatchState,
        policyHardIndicators: List<TeeEvidenceItem>,
        policySoftIndicators: List<TeeEvidenceItem>,
        supplementaryIndicators: List<TeeEvidenceItem>,
    ): List<TeeEvidenceSection> {
        return listOf(
            TeeEvidenceSection(
                title = "Trust",
                items = buildList {
                    add(
                        fact(
                            "Local chain",
                            if (artifacts.trust.chainSignatureValid) "Verified" else "Failed",
                            if (artifacts.trust.chainSignatureValid) TeeSignalLevel.PASS else TeeSignalLevel.FAIL
                        )
                    )
                    add(
                        fact(
                            "Trust root",
                            trustRootLabel(artifacts.trust.trustRoot),
                            trustLevel(artifacts)
                        )
                    )
                    add(
                        fact(
                            "Chain layout",
                            chainLayoutValue(artifacts),
                            chainLayoutLevel(artifacts)
                        )
                    )
                    add(fact("RKP", rkpValue(artifacts), rkpDisplayLevel(artifacts)))
                    add(fact("CRL", crlValue(artifacts), crlSignalLevel(artifacts)))
                    add(
                        fact(
                            "Root fingerprint",
                            shortFingerprint(artifacts.trust.rootFingerprint),
                            TeeSignalLevel.INFO
                        )
                    )
                },
            ),
            TeeEvidenceSection(
                title = "Attestation",
                items = buildList {
                    add(
                        fact(
                            "Tier",
                            tierValue(artifacts),
                            tierLevel(effectiveTier(artifacts))
                        )
                    )
                    add(fact("Versions", versionsValue(artifacts.snapshot), TeeSignalLevel.INFO))
                    add(
                        fact(
                            "Challenge",
                            challengeValue(artifacts.snapshot),
                            challengeLevel(artifacts.snapshot)
                        )
                    )
                    add(
                        fact(
                            "Verified boot",
                            verifiedBootValue(artifacts.snapshot),
                            verifiedBootLevel(artifacts.snapshot)
                        )
                    )
                    add(
                        fact(
                            "Boot consistency",
                            bootConsistencyValue(artifacts),
                            bootSignalLevel(artifacts)
                        )
                    )
                    add(
                        fact(
                            "Device IDs",
                            deviceInfoValue(artifacts.snapshot),
                            deviceInfoLevel(artifacts.snapshot)
                        )
                    )
                    add(
                        fact(
                            "Key properties",
                            keyPropertiesValue(artifacts.snapshot),
                            TeeSignalLevel.INFO
                        )
                    )
                    add(fact("User auth", authStateValue(artifacts.snapshot), TeeSignalLevel.INFO))
                    add(
                        fact(
                            "Application",
                            applicationInfoValue(artifacts.snapshot),
                            TeeSignalLevel.INFO
                        )
                    )
                },
            ),
            TeeEvidenceSection(
                title = "Checks",
                items = buildList {
                    add(
                        fact(
                            "Indicators",
                            indicatorValue(
                                policyHardIndicators = policyHardIndicators,
                                policySoftIndicators = policySoftIndicators,
                                supplementaryIndicators = supplementaryIndicators,
                            ),
                            indicatorLevel(
                                policyHardIndicators = policyHardIndicators,
                                policySoftIndicators = policySoftIndicators,
                                supplementaryIndicators = supplementaryIndicators,
                            ),
                        )
                    )
                    add(
                        fact(
                            "Key pair",
                            keyPairValue(artifacts),
                            if (artifacts.pairConsistency.keyMatchesCertificate) TeeSignalLevel.PASS else TeeSignalLevel.FAIL
                        )
                    )
                    add(
                        fact(
                            "AES-GCM",
                            aesGcmValue(artifacts),
                            aesGcmLevel(artifacts)
                        )
                    )
                    add(fact("Lifecycle", lifecycleValue(artifacts), lifecycleLevel(artifacts)))
                    add(
                        fact(
                            "Timing",
                            timingValue(artifacts),
                            if (artifacts.timing.suspicious) TeeSignalLevel.WARN else TeeSignalLevel.INFO
                        )
                    )
                    add(
                        fact(
                            "Timing side-channel",
                            timingSideChannelValue(artifacts),
                            timingSideChannelLevel(artifacts),
                            hiddenCopyText = artifacts.timingSideChannel.stackCopyPayload,
                        )
                    )
                    add(
                        fact(
                            "Oversized challenge",
                            oversizedChallengeValue(artifacts),
                            oversizedChallengeLevel(artifacts)
                        )
                    )
                    add(
                        fact(
                            "TEE Simulator generate-mode fingerprint",
                            generateModeAnomalyValue(artifacts),
                            generateModeAnomalyLevel(artifacts),
                        )
                    )
                    add(fact("Keybox", keyboxValue(artifacts), keyboxLevel(artifacts)))
                    add(
                        fact(
                            "Keystore2",
                            keystore2Value(artifacts),
                            if (artifacts.keystore2Hook.javaHookDetected) TeeSignalLevel.FAIL else TeeSignalLevel.INFO
                        )
                    )
                    add(
                        fact(
                            "Legacy keystore",
                            legacyKeystorePathValue(artifacts),
                            legacyKeystorePathLevel(artifacts)
                        )
                    )
                    add(
                        fact(
                            "listEntries",
                            listEntriesConsistencyValue(artifacts),
                            listEntriesConsistencyLevel(artifacts)
                        )
                    )
                    add(
                        fact(
                            "listEntriesBatched",
                            listEntriesBatchedValue(artifacts),
                            listEntriesBatchedLevel(artifacts)
                        )
                    )
                    add(
                        fact(
                            "Metadata key",
                            keyMetadataSemanticsValue(artifacts),
                            keyMetadataSemanticsLevel(artifacts)
                        )
                    )
                    add(
                        fact(
                            "Metadata shape",
                            keyMetadataShapeValue(artifacts),
                            keyMetadataShapeLevel(artifacts)
                        )
                    )
                    add(
                        fact(
                            "Pure cert",
                            pureCertificateValue(artifacts),
                            if (artifacts.pureCertificate.pureCertificateReturnsNullKey) TeeSignalLevel.PASS else TeeSignalLevel.FAIL
                        )
                    )
                    add(
                        fact(
                            "Pure cert level",
                            pureCertificateTopLevelSecurityValue(artifacts),
                            pureCertificateTopLevelSecurityLevel(artifacts)
                        )
                    )
                    add(
                        fact(
                            "Pure cert metadata",
                            pureCertificateMetadataSecurityValue(artifacts),
                            pureCertificateMetadataSecurityLevel(artifacts)
                        )
                    )
                    add(
                        fact(
                            "Operation path",
                            operationErrorPathValue(artifacts),
                            operationErrorPathLevel(artifacts)
                        )
                    )
                    add(
                        fact(
                            "Biometric TEE",
                            biometricIntegrationValue(artifacts),
                            biometricIntegrationLevel(artifacts)
                        )
                    )
                    add(
                        fact(
                            "Binder hook",
                            binderHookBootstrapValue(artifacts),
                            binderHookBootstrapLevel(artifacts)
                        )
                    )
                    add(
                        fact(
                            "Patch mode",
                            binderPatchModeValue(artifacts),
                            binderPatchModeLevel(artifacts)
                        )
                    )
                    add(
                        fact(
                            "Binder chain",
                            binderChainConsistencyValue(artifacts),
                            binderChainConsistencyLevel(artifacts)
                        )
                    )
                    add(
                        fact(
                            "Update path",
                            updateSubcomponentValue(artifacts),
                            if (artifacts.updateSubcomponent.keyNotFoundStyleFailure) TeeSignalLevel.FAIL else TeeSignalLevel.PASS
                        )
                    )
                    add(
                        fact(
                            "Pruning",
                            pruningValue(artifacts),
                            if (artifacts.pruning.suspicious) TeeSignalLevel.WARN else TeeSignalLevel.INFO
                        )
                    )
                    add(
                        fact(
                            "Dual algorithm",
                            dualAlgorithmValue(artifacts),
                            TeeSignalLevel.INFO
                        )
                    )
                    add(
                        fact(
                            "ID attestation",
                            idAttestationValue(artifacts),
                            if (artifacts.idAttestation.mismatches.isNotEmpty()) TeeSignalLevel.WARN else TeeSignalLevel.INFO
                        )
                    )
                    add(fact("StrongBox", strongBoxValue(artifacts), strongBoxLevel(artifacts)))
                    add(fact("Native", nativeValue(artifacts), nativeSignalLevel(artifacts)))
                    add(fact("Soter", artifacts.soter.summary, soterLevel(artifacts)))
                },
            ),
        )
    }

    private fun buildPatchState(artifacts: TeeScanArtifacts): TeePatchState {
        val runtimePatch = Build.VERSION.SECURITY_PATCH?.takeIf { it.isNotBlank() }
        val attestedPatch = artifacts.snapshot.osPatchLevel
        val grade = when {
            runtimePatch == null || attestedPatch == null -> TeePatchGrade.UNKNOWN
            runtimePatch == attestedPatch -> TeePatchGrade.MATCHED
            monthDistance(
                runtimePatch,
                attestedPatch
            )?.let { it <= 3 } == true -> TeePatchGrade.WARNING

            else -> TeePatchGrade.SUSPICIOUS
        }
        return TeePatchState(
            systemPatchLevel = runtimePatch,
            teePatchLevel = attestedPatch,
            vendorPatchLevel = artifacts.snapshot.vendorPatchLevel,
            bootPatchLevel = artifacts.snapshot.bootPatchLevel,
            grade = grade,
            summary = when (grade) {
                TeePatchGrade.MATCHED -> "Runtime and attested patch levels line up locally."
                TeePatchGrade.WARNING -> "Patch levels drift slightly but stay within a short window."
                TeePatchGrade.SUSPICIOUS -> "Runtime and attested patch levels drift by more than three months."
                TeePatchGrade.UNKNOWN -> "Patch comparison was unavailable."
            },
        )
    }

    private fun headlineFor(
        verdict: TeeVerdict,
        supplementaryIndicators: List<TeeEvidenceItem>,
    ): String = when (verdict) {
        TeeVerdict.CONSISTENT -> if (supplementaryIndicators.isNotEmpty()) {
            "Attestation aligned; local probes need review"
        } else {
            "Local TEE attestation checks aligned"
        }

        TeeVerdict.TAMPERED -> "Policy-backed attestation anomalies were detected"
        TeeVerdict.SUSPICIOUS -> "Policy-backed attestation evidence needs review"
        TeeVerdict.BROKEN -> "Hardware-backed local verification was not established"
        TeeVerdict.INCONCLUSIVE -> "Local verification stayed inconclusive"
        TeeVerdict.LOADING -> "TEE"
    }

    private fun summaryFor(
        verdict: TeeVerdict,
        artifacts: TeeScanArtifacts,
        policyHardIndicators: List<TeeEvidenceItem>,
        policySoftIndicators: List<TeeEvidenceItem>,
        supplementaryIndicators: List<TeeEvidenceItem>,
    ): String = when (verdict) {
        TeeVerdict.CONSISTENT -> supplementaryIndicators.firstOrNull()?.let { item ->
            "${item.body} Attestation and trust-path checks still aligned."
        } ?: "Attestation, trust path, and revocation checks line up."

        TeeVerdict.TAMPERED -> policyHardIndicators.firstOrNull()?.body
            ?: "Multiple hard anomaly indicators were raised."

        TeeVerdict.SUSPICIOUS -> policySoftIndicators.firstOrNull()?.body
            ?: "Policy-backed review signals suggest further review."

        TeeVerdict.BROKEN -> artifacts.snapshot.errorMessage
            ?: "Local verification could not establish hardware-backed trust."

        TeeVerdict.INCONCLUSIVE -> "Signals were mixed and did not converge on a stable local result."
        TeeVerdict.LOADING -> "Collecting local attestation and keystore evidence."
    }

    private fun collapsedSummaryFor(
        verdict: TeeVerdict,
        policyHardIndicators: List<TeeEvidenceItem>,
        policySoftIndicators: List<TeeEvidenceItem>,
        supplementaryIndicators: List<TeeEvidenceItem>,
    ): String = when (verdict) {
        TeeVerdict.CONSISTENT -> if (supplementaryIndicators.isNotEmpty()) {
            "Aligned • local review"
        } else {
            "Checks aligned"
        }

        TeeVerdict.TAMPERED -> "${policyHardIndicators.size} policy anomaly"
        TeeVerdict.SUSPICIOUS -> "${policySoftIndicators.size} policy review"
        TeeVerdict.BROKEN -> "No hardware trust"
        TeeVerdict.INCONCLUSIVE -> "Mixed signals"
        TeeVerdict.LOADING -> "Scanning"
    }

    private fun trustSummaryFor(artifacts: TeeScanArtifacts): String {
        return buildString {
            append("Local trust path: ")
            append(trustRootLabel(normalizeTrustRoot(artifacts.trust.trustRoot)))
            append(", chain ")
            append(if (artifacts.trust.chainSignatureValid) "verified" else "failed")
            if (artifacts.rkp.provisioned) {
                append(", ")
                append(
                    when {
                        !artifacts.trust.chainSignatureValid -> "RKP observed on an invalid local chain"
                        hasLocalTrustReviewSignals(artifacts) -> "RKP observed, local trust needs review"
                        else -> "RKP observed"
                    }
                )
            } else if (artifacts.rkp.consistencyIssue != null) {
                append(", provisioning needs review")
            }
        }
    }

    private fun fact(
        title: String,
        body: String,
        level: TeeSignalLevel,
        hiddenCopyText: String? = null,
    ): TeeEvidenceItem = TeeEvidenceItem(
        title = title,
        body = body,
        level = level,
        hiddenCopyText = hiddenCopyText,
    )

    private fun tierValue(artifacts: TeeScanArtifacts): String {
        val effective = effectiveTier(artifacts)
        val snapshot = artifacts.snapshot
        val attest = snapshot.attestationTier?.displayName()
        val keymaster = snapshot.keymasterTier?.displayName()
        val strongBoxAttestation = artifacts.strongBox.attestationTier
            .takeIf { artifacts.strongBox.available || it == TeeTier.STRONGBOX }
            ?.displayName()
        return when {
            attest == null && keymaster == null && strongBoxAttestation == null -> effective.displayName()
            else -> buildString {
                append(effective.displayName())
                attest?.let {
                    append(" • attest ")
                    append(it)
                }
                keymaster?.let {
                    append(" • keymaster ")
                    append(it)
                }
                if (strongBoxAttestation != null && strongBoxAttestation != effective.displayName()) {
                    append(" • sb attest ")
                    append(strongBoxAttestation)
                }
            }
        }
    }

    private fun effectiveTier(artifacts: TeeScanArtifacts): TeeTier {
        return when {
            artifacts.snapshot.tier == TeeTier.STRONGBOX -> TeeTier.STRONGBOX
            artifacts.snapshot.tier != TeeTier.TEE -> artifacts.snapshot.tier
            artifacts.strongBox.available && artifacts.strongBox.attestationTier == TeeTier.STRONGBOX ->
                TeeTier.STRONGBOX

            artifacts.strongBox.available && artifacts.strongBox.keyInfoLevel == "StrongBox" ->
                TeeTier.STRONGBOX

            else -> artifacts.snapshot.tier
        }
    }

    private fun versionsValue(snapshot: AttestationSnapshot): String {
        val attestation = snapshot.attestationVersion?.toString() ?: "n/a"
        val keymaster = snapshot.keymasterVersion?.toString() ?: "n/a"
        val os = snapshot.osVersion ?: "n/a"
        return "attest $attestation • keymaster $keymaster • Android $os"
    }

    private fun challengeValue(snapshot: AttestationSnapshot): String {
        return when {
            snapshot.trustedAttestationIndex == null -> "Unavailable"
            snapshot.challengeVerified -> snapshot.challengeSummary?.let { "Matched • $it" }
                ?: "Matched"

            else -> snapshot.challengeSummary?.let { "Mismatch • $it" } ?: "Mismatch"
        }
    }

    private fun verifiedBootValue(snapshot: AttestationSnapshot): String {
        val root = snapshot.rootOfTrust ?: return "Unavailable"
        val state = root.verifiedBootState ?: "Unknown"
        val lock = when (root.deviceLocked) {
            true -> "locked"
            false -> "unlocked"
            null -> "lock unknown"
        }
        val hash = root.verifiedBootHashHex?.take(12)
        return buildString {
            append(state)
            append(" • ")
            append(lock)
            hash?.let {
                append(" • ")
                append(it)
            }
        }
    }

    private fun patchValue(patchState: TeePatchState): String {
        return buildString {
            append("runtime ")
            append(patchState.systemPatchLevel ?: "n/a")
            append(" • attest ")
            append(patchState.teePatchLevel ?: "n/a")
            if (patchState.vendorPatchLevel != null || patchState.bootPatchLevel != null) {
                append(" • vendor ")
                append(patchState.vendorPatchLevel ?: "n/a")
                append(" • boot ")
                append(patchState.bootPatchLevel ?: "n/a")
            }
        }
    }

    private fun deviceInfoValue(snapshot: AttestationSnapshot): String {
        val labels = snapshot.deviceInfo.asDisplayMap().keys
        if (labels.isEmpty()) {
            return if (snapshot.deviceUniqueAttestation) {
                "No comparable IDs • unique attestation requested"
            } else {
                "Not included in attestation"
            }
        }
        return buildString {
            append(labels.joinToString(separator = ", "))
            if (snapshot.deviceUniqueAttestation) {
                append(" • unique")
            }
        }
    }

    private fun keyPropertiesValue(snapshot: AttestationSnapshot): String {
        val props = snapshot.keyProperties
        return listOfNotNull(
            props.algorithm?.let { algorithm ->
                props.keySize?.let { "$algorithm $it" } ?: algorithm
            },
            props.ecCurve,
            props.origin,
            props.rollbackResistant.takeIf { it }?.let { "rollback resistant" },
        ).ifEmpty { listOf("Unavailable") }.joinToString(separator = " • ")
    }

    private fun authStateValue(snapshot: AttestationSnapshot): String {
        val auth = snapshot.authState
        return when {
            auth.noAuthRequired == true -> "No user auth required"
            auth.userAuthTypes.isNotEmpty() -> buildString {
                append(auth.userAuthTypes.joinToString(separator = "/"))
                auth.authTimeoutSeconds?.let {
                    append(" • ")
                    append(it)
                    append("s timeout")
                }
            }

            auth.trustedConfirmationRequired || auth.trustedPresenceRequired || auth.unlockedDeviceRequired -> {
                buildList {
                    if (auth.trustedConfirmationRequired) add("confirmation")
                    if (auth.trustedPresenceRequired) add("presence")
                    if (auth.unlockedDeviceRequired) add("unlocked")
                }.joinToString(separator = " • ")
            }

            else -> "Unavailable"
        }
    }

    private fun applicationInfoValue(snapshot: AttestationSnapshot): String {
        val packages = snapshot.applicationInfo.packageNames
        val digests = snapshot.applicationInfo.signatureDigestsSha256.size
        return when {
            packages.isNotEmpty() -> "${packages.size} package(s) • $digests signer digest(s)"
            snapshot.applicationInfo.rawBytesHex != null -> "Raw app attestation present"
            else -> "Unavailable"
        }
    }

    private fun chainLayoutValue(artifacts: TeeScanArtifacts): String {
        val trustedIndex =
            artifacts.chainStructure.trustedAttestationIndex?.let { "#${it + 1}" } ?: "n/a"
        return "len ${artifacts.chainStructure.chainLength} • ext ${artifacts.chainStructure.attestationExtensionCount} • trusted $trustedIndex"
    }

    private fun rkpValue(artifacts: TeeScanArtifacts): String {
        return when {
            artifacts.rkp.provisioned && !artifacts.trust.chainSignatureValid -> "Observed • local chain failed"
            artifacts.rkp.provisioned && hasLocalTrustReviewSignals(artifacts) -> "Observed • local trust needs review"
            artifacts.rkp.provisioned && artifacts.rkp.validityDays != null -> "Provisioned • ${artifacts.rkp.validityDays}d leaf"
            artifacts.rkp.provisioned -> "Provisioned"
            artifacts.rkp.consistencyIssue != null -> "Review provisioning"
            else -> "Not observed"
        }
    }

    private fun crlValue(artifacts: TeeScanArtifacts): String {
        val network = artifacts.crl.networkState
        val sourceLabel = when {
            network.mode == TeeNetworkMode.ACTIVE -> "Online"
            network.mode == TeeNetworkMode.CONSENT_REQUIRED -> "Consent required"
            network.mode == TeeNetworkMode.SKIPPED -> "Disabled in Settings"
            network.mode == TeeNetworkMode.ERROR -> "Refresh failed"
            network.mode == TeeNetworkMode.INACTIVE -> "Offline only"
            else -> "Offline only"
        }
        return buildString {
            append(sourceLabel)
            if (network.mode == TeeNetworkMode.ACTIVE) {
                append(" • ")
                append(
                    if (artifacts.crl.revokedCertificates.isEmpty()) {
                        "clean"
                    } else {
                        "${artifacts.crl.revokedCertificates.size} revoked"
                    },
                )
            }
            network.detail?.takeIf { it.isNotBlank() }?.let { detail ->
                append(" • ")
                append(detail)
            }
        }
    }

    private fun keyPairValue(artifacts: TeeScanArtifacts): String {
        val base = if (artifacts.pairConsistency.keyMatchesCertificate) {
            "Signature matched certificate"
        } else {
            "Public key mismatch"
        }
        return artifacts.pairConsistency.medianSignMicros?.let { "$base • ${it}us" } ?: base
    }

    private fun lifecycleValue(artifacts: TeeScanArtifacts): String {
        return when {
            artifacts.lifecycle.deleteRemovedAlias && artifacts.lifecycle.regeneratedFreshMaterial -> "Delete ok • fresh material"
            else -> "Delete/regenerate contradiction"
        }
    }

    private fun aesGcmValue(artifacts: TeeScanArtifacts): String {
        val result = artifacts.aesGcm
        return when {
            !result.executed -> "Skipped"
            !result.roundTripSucceeded -> buildString {
                append("Round-trip failed")
                result.keyInfoLevel?.let {
                    append(" • ")
                    append(it)
                }
            }

            result.insideSecureHardware == true -> buildString {
                append("Round-trip ok")
                result.keyInfoLevel?.let {
                    append(" • ")
                    append(it)
                }
                result.encryptMicros?.let {
                    append(" • ")
                    append(it)
                    append("us enc")
                }
            }

            else -> buildString {
                append("Round-trip ok • software-backed")
                result.keyInfoLevel?.let {
                    append(" • ")
                    append(it)
                }
            }
        }
    }

    private fun timingValue(artifacts: TeeScanArtifacts): String {
        val median = artifacts.timing.medianMicros?.let { "${it}us" } ?: "n/a"
        return if (artifacts.timing.suspicious) {
            "Fast/steady • $median"
        } else {
            "Median $median"
        }
    }

    private fun timingSideChannelValue(artifacts: TeeScanArtifacts): String {
        val result = artifacts.timingSideChannel
        val skipSignature = timingSideChannelSkipSignature(result)
        val timerSource = timingSideChannelTimerSourceLabel(result.timerSource, result.detail)
        val thresholdMillis = String.format(Locale.US, "%.1f", TIMING_SIDE_CHANNEL_THRESHOLD_MILLIS)
        val affinity = when {
            result.affinity.isBlank() || result.affinity == "unknown" -> "affinity unknown"
            else -> result.affinity
        }
        if (skipSignature != null) {
            // skip 命中 patch signature 时，row 文案直接切到 patch-mode，可视层不再展示“measurement unavailable”这种弱语义。
            // When skip hits a patch signature, switch the row text directly to patch-mode wording instead of weaker "measurement unavailable" phrasing.
            return listOf(skipSignature.rowLabel, timerSource, affinity)
                .filter { it.isNotBlank() }
                .joinToString(separator = " • ")
        }
        val avgAttested = result.avgAttestedMillis?.let { String.format(Locale.US, "%.3fms", it) } ?: "n/a"
        val avgNonAttested = result.avgNonAttestedMillis?.let { String.format(Locale.US, "%.3fms", it) } ?: "n/a"
        val diff = result.diffMillis?.let { String.format(Locale.US, "%.3fms", it) } ?: "n/a"
        val state = when {
            !result.probeRan -> "Skipped"
            !result.measurementAvailable -> "Measurement unavailable"
            result.suspicious -> "Positive"
            else -> "Not positive"
        }
        val filtered = Regex("filteredBadSamples=\\d+/\\d+")
            .find(result.detail)
            ?.value
            ?.let { " • $it" }
            .orEmpty()
        val reason = result.failureReason?.takeIf { it.isNotBlank() }?.let { " • reason $it" }.orEmpty()
        return "$timerSource • $affinity • attested $avgAttested • non-attested $avgNonAttested • diff $diff$filtered • threshold ±${thresholdMillis}ms • $state$reason"
    }

    private fun timingSideChannelSummary(artifacts: TeeScanArtifacts): String {
        val result = artifacts.timingSideChannel
        timingSideChannelSkipSignature(result)?.let { return it.summary }
        val timerSource = timingSideChannelTimerSourceLabel(result.timerSource, result.detail)
        val thresholdMillis = String.format(Locale.US, "%.1f", TIMING_SIDE_CHANNEL_THRESHOLD_MILLIS)
        if (!result.measurementAvailable) {
            return "$timerSource timing side-channel could not finish measurement; ${result.failureReason ?: "reason unavailable"}."
        }
        val thresholdDirection = result.diffMillis?.let { diff ->
            when {
                diff > TIMING_SIDE_CHANNEL_THRESHOLD_MILLIS -> "diff exceeded +${thresholdMillis}ms"
                diff < -TIMING_SIDE_CHANNEL_THRESHOLD_MILLIS -> "diff went below -${thresholdMillis}ms"
                else -> "diff stayed within +/-${thresholdMillis}ms"
            }
        } ?: "diff unavailable"
        return "$timerSource timing side-channel stayed supplementary; $thresholdDirection."
    }

    private fun timingSideChannelTimerSourceLabel(timerSource: String, detail: String): String {
        val normalized = timerSource.lowercase(Locale.US)
        val lowered = detail.lowercase(Locale.US)
        return when {
            "cntvct" in normalized || "register" in normalized -> "Register timer"
            "monotonic" in normalized || "nano" in normalized -> "Fallback timer"
            "register" in lowered -> "Register timer"
            "fallback" in lowered -> "Fallback timer"
            else -> "Timer source unspecified"
        }
    }

    private fun keyboxValue(artifacts: TeeScanArtifacts): String {
        return when {
            !artifacts.keyboxImport.executed -> "Skipped"
            artifacts.keyboxImport.markerPreserved -> "Marker preserved"
            else -> "Marker replaced"
        }
    }

    private fun oversizedChallengeValue(artifacts: TeeScanArtifacts): String {
        return if (artifacts.oversizedChallenge.acceptedOversizedChallenge) {
            "Accepted ${artifacts.oversizedChallenge.acceptedSizesLabel()}"
        } else {
            "Rejected ${artifacts.oversizedChallenge.attemptedSizesLabel()}"
        }
    }

    private fun generateModeAnomalyValue(artifacts: TeeScanArtifacts): String {
        return when (generateModeAnomalyState(artifacts)) {
            GenerateModeAnomalyState.MATCHED ->
                "Matched TEE Simulator generate-mode fingerprint."

            GenerateModeAnomalyState.CLEAN ->
                "No TEE Simulator generate-mode fingerprint observed."

            GenerateModeAnomalyState.UNAVAILABLE -> "TEE Simulator generate-mode fingerprint probe unavailable."
        }
    }

    private fun keystore2Value(artifacts: TeeScanArtifacts): String {
        return when {
            artifacts.keystore2Hook.javaHookDetected -> "Java-style reply"
            artifacts.keystore2Hook.nativeStyleResponse -> "Native-style reply"
            !artifacts.keystore2Hook.available -> "Unavailable"
            else -> artifacts.keystore2Hook.errorCode?.let { "Error $it" } ?: "Unexpected reply"
        }
    }

    private fun pureCertificateValue(artifacts: TeeScanArtifacts): String {
        return if (artifacts.pureCertificate.pureCertificateReturnsNullKey) {
            "Null key as expected"
        } else {
            "Returned a key object"
        }
    }

    private fun pureCertificateTopLevelSecurityValue(artifacts: TeeScanArtifacts): String {
        return when {
            !artifacts.pureCertificateSecurityLevel.executed -> "Skipped"
            artifacts.pureCertificateSecurityLevel.securityLevelPresent -> "Security level exposed"
            else -> "No security level exposed"
        }
    }

    private fun pureCertificateMetadataSecurityValue(artifacts: TeeScanArtifacts): String {
        return when {
            !artifacts.pureCertificateSecurityLevel.executed -> "Skipped"
            artifacts.pureCertificateSecurityLevel.metadataSecurityLevelPresent -> "Metadata security level exposed"
            else -> "No metadata security level exposed"
        }
    }

    private fun keyMetadataSemanticsValue(artifacts: TeeScanArtifacts): String {
        val result = artifacts.keyMetadataSemantics
        return when {
            !result.executed -> "Skipped"
            result.usesKeyIdDomain && result.aliasCleared -> "KEY_ID normalized"
            else -> "Descriptor mismatch"
        }
    }

    private fun keyMetadataShapeValue(artifacts: TeeScanArtifacts): String {
        val result = artifacts.keyMetadataShape
        return when {
            !result.executed -> "Skipped"
            result.modificationTimeValid && result.hasOriginTag -> "System fields present"
            else -> "System fields missing"
        }
    }

    private fun operationErrorPathValue(artifacts: TeeScanArtifacts): String {
        val result = artifacts.operationErrorPath
        val status = when {
            !result.executed -> "Skipped"
            !result.createOperationSucceeded -> "createOperation failed"
            !result.updateAadServiceSpecific -> "updateAad mismatch"
            !result.oversizedUpdateRejected -> "Oversized update accepted"
            !result.abortInvalidatedHandle -> "Abort left operation alive"
            result.fallbackCompatParamsUsed -> "Compatibility params required"
            else -> "Native-style errors"
        }
        val detail = result.detail.takeIf { it.isNotBlank() } ?: return status
        return "$status • $detail"
    }

    private fun updateSubcomponentValue(artifacts: TeeScanArtifacts): String {
        return when {
            artifacts.updateSubcomponent.keyNotFoundStyleFailure -> "Key-not-found style failure"
            artifacts.updateSubcomponent.updateSucceeded -> "No anomaly"
            else -> "Unexpected failure"
        }
    }

    private fun pruningValue(artifacts: TeeScanArtifacts): String {
        return if (artifacts.pruning.operationsCreated == 0) {
            "Skipped"
        } else {
            "${artifacts.pruning.invalidatedOperations}/${artifacts.pruning.operationsCreated} invalidated"
        }
    }

    private fun dualAlgorithmValue(artifacts: TeeScanArtifacts): String {
        return if (artifacts.dualAlgorithm.mismatchDetected) {
            "RSA/EC chain difference observed"
        } else {
            "RSA/EC chains aligned"
        }
    }

    private fun idAttestationValue(artifacts: TeeScanArtifacts): String {
        return when {
            !artifacts.idAttestation.probeRan -> "Skipped"
            artifacts.idAttestation.mismatches.isNotEmpty() -> "${artifacts.idAttestation.mismatches.size} mismatch(es)"
            artifacts.idAttestation.unavailableFields.size >= 5 -> "No comparable IDs exposed"
            artifacts.idAttestation.unavailableFields.isNotEmpty() -> "${artifacts.idAttestation.unavailableFields.size} comparable field(s) not exposed"
            else -> "Available fields aligned"
        }
    }

    private fun biometricIntegrationValue(artifacts: TeeScanArtifacts): String {
        val result = artifacts.biometricIntegration
        return when {
            !result.executed -> "Skipped"
            !result.strongBiometricAvailable -> "Strong biometric unavailable"
            result.keyCreated && result.keyRetrieved -> "User-auth key path available"
            result.keyCreated -> "Created but getKey() returned null"
            else -> "User-auth key path failed"
        }
    }

    private fun binderChainConsistencyValue(artifacts: TeeScanArtifacts): String {
        val result = artifacts.binderChainConsistency
        val status = when {
            !result.executed -> "Skipped"
            !result.hookInstalled -> "Hook bootstrap failed"
            result.suspiciousLeafIssuerSpki -> "Leaf SPKI matched issuer SPKI"
            !result.activeProbeSecondCycleSucceeded -> "Repeated active probe failed"
            !result.deleteEntryRemovedAlias -> "deleteEntry left alias present"
            !result.keystoreChainAvailable -> "Java chain unavailable"
            !result.binderMaterialAvailable -> "Binder chain unavailable"
            !result.generateVsGetKeyEntryLeafMatches -> "generateKey leaf differed from getKeyEntry"
            !result.generateVsGetKeyEntryChainMatches -> "generateKey chain differed from getKeyEntry"
            result.chainMatches -> "Java and binder chains aligned"
            result.leafMatches -> "Leaf matched but chain diverged"
            else -> "Leaf and chain diverged"
        }
        val detail = result.detail.takeIf { it.isNotBlank() } ?: return status
        return "$status • $detail"
    }

    private fun binderHookBootstrapValue(artifacts: TeeScanArtifacts): String {
        val result = artifacts.binderHookBootstrap
        return when {
            !result.executed -> "Skipped"
            result.hookInstalled -> "Hook installed"
            else -> "Hook bootstrap failed"
        }
    }

    private fun legacyKeystorePathValue(artifacts: TeeScanArtifacts): String {
        val result = artifacts.legacyKeystorePath
        return when {
            !result.executed -> "Skipped"
            !result.hookInstalled -> "Hook unavailable"
            !result.legacyMaterialAvailable -> "Legacy path not observed"
            result.chainMatches -> "Legacy path aligned"
            result.userCertCaptured || result.caCertCaptured -> "Legacy path captured but diverged"
            else -> "Legacy path unavailable"
        }
    }

    private fun binderPatchModeValue(artifacts: TeeScanArtifacts): String {
        val result = artifacts.binderPatchMode
        return when {
            !result.executed -> "Skipped"
            !result.hookInstalled -> "Hook unavailable"
            result.leafDiffers -> "Leaf differed between generateKey and getKeyEntry"
            result.chainDiffers -> "Chain differed between generateKey and getKeyEntry"
            result.generateMaterialAvailable && result.keyEntryMaterialAvailable -> "generateKey/getKeyEntry aligned"
            else -> "Capture unavailable"
        }
    }

    private fun strongBoxValue(artifacts: TeeScanArtifacts): String {
        return when {
            artifacts.strongBox.hardFailures.isNotEmpty() -> artifacts.strongBox.hardFailures.first()
            artifacts.strongBox.warnings.isNotEmpty() -> artifacts.strongBox.warnings.first()
            !artifacts.strongBox.requested && !artifacts.strongBox.advertised -> "Not advertised"
            artifacts.strongBox.available -> buildString {
                append("Available")
                artifacts.strongBox.keyInfoLevel?.let {
                    append(" • ")
                    append(it)
                }
            }

            artifacts.strongBox.requested -> "Not confirmed"
            else -> "Skipped"
        }
    }

    private fun listEntriesConsistencyValue(artifacts: TeeScanArtifacts): String {
        val result = artifacts.listEntriesConsistency
        return when {
            !result.executed -> "Skipped"
            result.badParcelableLikeCrash -> "BadParcelable-style crash"
            result.inconsistent -> "containsAlias/listEntries mismatch"
            else -> "containsAlias and aliases aligned"
        }
    }

    private fun listEntriesBatchedValue(artifacts: TeeScanArtifacts): String {
        val result = artifacts.listEntriesBatched
        return when {
            !result.executed -> "Skipped"
            result.cursorEchoed -> "Cursor echoed in page"
            result.expectedNextMissing -> "Expected next alias missing"
            else -> "Cursor semantics aligned"
        }
    }

    private fun aesGcmLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
        return when {
            !artifacts.aesGcm.executed -> TeeSignalLevel.INFO
            !artifacts.aesGcm.roundTripSucceeded -> TeeSignalLevel.FAIL
            artifacts.aesGcm.insideSecureHardware == false -> TeeSignalLevel.WARN
            else -> TeeSignalLevel.PASS
        }
    }

    private fun listEntriesConsistencyLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
        val result = artifacts.listEntriesConsistency
        return when {
            !result.executed -> TeeSignalLevel.INFO
            result.badParcelableLikeCrash || result.inconsistent -> TeeSignalLevel.FAIL
            else -> TeeSignalLevel.PASS
        }
    }

    private fun listEntriesBatchedLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
        val result = artifacts.listEntriesBatched
        return when {
            !result.executed -> TeeSignalLevel.INFO
            result.cursorEchoed -> TeeSignalLevel.FAIL
            result.expectedNextMissing -> TeeSignalLevel.WARN
            else -> TeeSignalLevel.PASS
        }
    }

    private fun keyMetadataSemanticsLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
        val result = artifacts.keyMetadataSemantics
        return when {
            !result.executed -> TeeSignalLevel.INFO
            result.usesKeyIdDomain && result.aliasCleared -> TeeSignalLevel.PASS
            else -> TeeSignalLevel.FAIL
        }
    }

    private fun keyMetadataShapeLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
        val result = artifacts.keyMetadataShape
        return when {
            !result.executed -> TeeSignalLevel.INFO
            result.modificationTimeValid && result.hasOriginTag -> TeeSignalLevel.PASS
            else -> TeeSignalLevel.FAIL
        }
    }

    private fun pureCertificateTopLevelSecurityLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
        val result = artifacts.pureCertificateSecurityLevel
        return when {
            !result.executed -> TeeSignalLevel.INFO
            result.securityLevelPresent -> TeeSignalLevel.FAIL
            else -> TeeSignalLevel.PASS
        }
    }

    private fun pureCertificateMetadataSecurityLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
        val result = artifacts.pureCertificateSecurityLevel
        return when {
            !result.executed -> TeeSignalLevel.INFO
            result.metadataSecurityLevelPresent -> TeeSignalLevel.INFO
            else -> TeeSignalLevel.PASS
        }
    }

    private fun operationErrorPathLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
        val result = artifacts.operationErrorPath
        return when {
            !result.executed -> TeeSignalLevel.INFO
            !result.createOperationSucceeded ||
                !result.updateAadServiceSpecific ||
                !result.oversizedUpdateRejected ||
                !result.abortInvalidatedHandle -> TeeSignalLevel.FAIL
            result.fallbackCompatParamsUsed -> TeeSignalLevel.WARN

            else -> TeeSignalLevel.PASS
        }
    }

    private fun biometricIntegrationLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
        val result = artifacts.biometricIntegration
        return when {
            !result.executed -> TeeSignalLevel.INFO
            !result.strongBiometricAvailable -> TeeSignalLevel.INFO
            result.keyCreated && result.keyRetrieved -> TeeSignalLevel.PASS
            else -> TeeSignalLevel.FAIL
        }
    }

    private fun binderChainConsistencyLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
        val result = artifacts.binderChainConsistency
        return when {
            !result.executed -> TeeSignalLevel.INFO
            !result.hookInstalled -> TeeSignalLevel.FAIL
            result.suspiciousLeafIssuerSpki -> TeeSignalLevel.FAIL
            !result.activeProbeSecondCycleSucceeded -> TeeSignalLevel.FAIL
            !result.deleteEntryRemovedAlias -> TeeSignalLevel.FAIL
            !result.keystoreChainAvailable || !result.binderMaterialAvailable -> TeeSignalLevel.INFO
            !result.generateVsGetKeyEntryLeafMatches || !result.generateVsGetKeyEntryChainMatches -> TeeSignalLevel.FAIL
            result.chainMatches -> TeeSignalLevel.PASS
            else -> TeeSignalLevel.FAIL
        }
    }

    private fun binderHookBootstrapLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
        val result = artifacts.binderHookBootstrap
        return when {
            !result.executed -> TeeSignalLevel.INFO
            result.hookInstalled -> TeeSignalLevel.PASS
            else -> TeeSignalLevel.FAIL
        }
    }

    private fun legacyKeystorePathLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
        val result = artifacts.legacyKeystorePath
        return when {
            !result.executed -> TeeSignalLevel.INFO
            !result.hookInstalled -> TeeSignalLevel.INFO
            !result.legacyMaterialAvailable -> TeeSignalLevel.INFO
            result.chainMatches -> TeeSignalLevel.PASS
            else -> TeeSignalLevel.WARN
        }
    }

    private fun binderPatchModeLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
        val result = artifacts.binderPatchMode
        return when {
            !result.executed -> TeeSignalLevel.INFO
            !result.hookInstalled -> TeeSignalLevel.FAIL
            result.leafDiffers || result.chainDiffers -> TeeSignalLevel.FAIL
            result.generateMaterialAvailable && result.keyEntryMaterialAvailable -> TeeSignalLevel.PASS
            else -> TeeSignalLevel.INFO
        }
    }

    private fun nativeValue(artifacts: TeeScanArtifacts): String {
        return when {
            artifacts.native.trickyStoreDetected -> buildString {
                append(nativeMethodSummary(artifacts))
                append(" • ")
                append(artifacts.native.trickyStoreTimerSource)
                append(" • ")
                append(artifacts.native.trickyStoreAffinityStatus)
                nativeTimingStatsSummary(artifacts)?.let {
                    append('\n')
                    append(it)
                }
                artifacts.native.trickyStoreDetails
                    .takeUnless { it == "Native probe unavailable" }
                    ?.takeIf { it.isNotBlank() }
                    ?.let {
                        append('\n')
                        append(it)
                    }
            }
            artifacts.native.trickyStoreDetails != "Native probe unavailable" &&
                !hasNativeReviewSignals(artifacts) &&
                !artifacts.native.leafDerPrimaryDetected -> buildString {
                append(artifacts.native.trickyStoreDetails)
                nativeTimingStatsSummary(artifacts)?.let {
                    append("\n")
                    append(it)
                }
                if (artifacts.native.trickyStoreTimerSource != "unknown") {
                    append("\n")
                    append(artifacts.native.trickyStoreTimerSource)
                    append(" • ")
                    append(artifacts.native.trickyStoreAffinityStatus)
                }
            }
            artifacts.native.leafDerPrimaryDetected -> "Primary DER hit"
            hasNativeReviewSignals(artifacts) -> buildString {
                append(nativeReviewSummary(artifacts))
                if (artifacts.native.syscallMismatchDetected) {
                    append('\n')
                    append(syscallMismatchExplanation())
                }
            }

            else -> "No local process-side anomaly"
        }
    }

    private fun nativeTimingStatsSummary(artifacts: TeeScanArtifacts): String? {
        return buildList {
            val suspiciousRuns = artifacts.native.trickyStoreTimingSuspiciousRunCount
            val totalRuns = artifacts.native.trickyStoreTimingRunCount
            if (suspiciousRuns != null && totalRuns != null && totalRuns > 0) {
                add("$suspiciousRuns/$totalRuns suspicious runs")
            }
            artifacts.native.trickyStoreTimingMedianGapNs
                ?.takeIf { it > 0L }
                ?.let { add("median gap ${formatNanoseconds(it)}") }
            artifacts.native.trickyStoreTimingGapMadNs
                ?.takeIf { it > 0L }
                ?.let { add("gap MAD ${formatNanoseconds(it)}") }
            artifacts.native.trickyStoreTimingMedianNoiseFloorNs
                ?.takeIf { it > 0L }
                ?.let { add("noise floor ${formatNanoseconds(it)}") }
            artifacts.native.trickyStoreTimingMedianRatioPercent
                ?.takeIf { it > 0 }
                ?.let { add("median ratio ${formatRatioPercent(it)}") }
        }.takeIf { it.isNotEmpty() }?.joinToString(separator = " • ")
    }

    private fun formatNanoseconds(valueNs: Long): String {
        return when {
            valueNs >= 1_000_000L -> String.format(Locale.US, "%.2fms", valueNs / 1_000_000.0)
            valueNs >= 100L -> String.format(Locale.US, "%.1fus", valueNs / 1_000.0)
            else -> "${valueNs}ns"
        }
    }

    private fun formatRatioPercent(percent: Int): String {
        return String.format(Locale.US, "%.2fx", percent / 100.0)
    }

    private fun bootConsistencyValue(artifacts: TeeScanArtifacts): String {
        val result = artifacts.bootConsistency
        val root = artifacts.snapshot.rootOfTrust
        return when {
            result.hasHardAnomaly -> "Mismatch • ${result.detail}"
            root == null -> "Unavailable • ${result.detail}"
            !result.runtimePropsAvailable -> "Unavailable • ${result.detail}"
            result.runtimeComparisonPerformed ->
                "Matched • ${result.detail}"

            else -> "State only • ${result.detail}"
        }
    }

    private fun patchSignalValue(patchState: TeePatchState): String = when (patchState.grade) {
        TeePatchGrade.MATCHED -> "Aligned"
        TeePatchGrade.WARNING -> "Short drift"
        TeePatchGrade.SUSPICIOUS -> "Wide drift"
        TeePatchGrade.UNKNOWN -> "Unavailable"
    }

    private fun crlSignalValue(artifacts: TeeScanArtifacts): String = when {
        artifacts.crl.revokedCertificates.isNotEmpty() -> "Revoked"
        artifacts.crl.networkState.mode == TeeNetworkMode.ACTIVE -> "Online"
        artifacts.crl.networkState.mode == TeeNetworkMode.CONSENT_REQUIRED -> "Consent"
        artifacts.crl.networkState.mode == TeeNetworkMode.SKIPPED -> "Disabled"
        artifacts.crl.networkState.mode == TeeNetworkMode.ERROR -> "Error"
        else -> "Offline"
    }

    private fun nativeSignalValue(artifacts: TeeScanArtifacts): String = when {
        artifacts.native.trickyStoreDetected -> nativePrimarySignalLabel(artifacts)
        artifacts.native.leafDerPrimaryDetected -> "Primary DER"
        artifacts.native.leafDerSecondaryDetected -> "Secondary DER"
        artifacts.native.tracingDetected -> "Tracing"
        artifacts.native.suspiciousMappings.isNotEmpty() -> "Mappings"
        artifacts.native.syscallMismatchDetected -> "Syscall mismatch"
        else -> "Review"
    }

    private fun chainLayoutLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
        artifacts.chainStructure.provisioningConsistencyIssue -> TeeSignalLevel.WARN
        else -> TeeSignalLevel.INFO
    }

    private fun challengeLevel(snapshot: AttestationSnapshot): TeeSignalLevel = when {
        snapshot.trustedAttestationIndex == null -> TeeSignalLevel.INFO
        snapshot.challengeVerified -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.FAIL
    }

    private fun verifiedBootLevel(snapshot: AttestationSnapshot): TeeSignalLevel {
        val bootState = snapshot.rootOfTrust?.verifiedBootState ?: return TeeSignalLevel.INFO
        return if (bootState == "Verified") TeeSignalLevel.PASS else TeeSignalLevel.WARN
    }

    private fun bootSignalValue(artifacts: TeeScanArtifacts): String {
        val root = artifacts.snapshot.rootOfTrust
        return when {
            artifacts.bootConsistency.hasHardAnomaly -> "Mismatch"
            root == null -> "Unavailable"
            !artifacts.bootConsistency.runtimePropsAvailable -> "Unavailable"
            artifacts.bootConsistency.runtimeComparisonPerformed -> "Matched"
            else -> "State only"
        }
    }

    private fun bootSignalLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
        val root = artifacts.snapshot.rootOfTrust
        return when {
            artifacts.bootConsistency.hasHardAnomaly -> TeeSignalLevel.FAIL
            root == null -> TeeSignalLevel.INFO
            !artifacts.bootConsistency.runtimePropsAvailable -> TeeSignalLevel.INFO
            artifacts.bootConsistency.runtimeComparisonPerformed -> TeeSignalLevel.PASS
            else -> TeeSignalLevel.INFO
        }
    }

    private fun deviceInfoLevel(snapshot: AttestationSnapshot): TeeSignalLevel {
        return if (snapshot.deviceInfo.asDisplayMap()
                .isEmpty()
        ) TeeSignalLevel.INFO else TeeSignalLevel.PASS
    }

    private fun trustLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
        !artifacts.trust.chainSignatureValid -> TeeSignalLevel.FAIL
        hasLocalTrustReviewSignals(artifacts) -> TeeSignalLevel.WARN
        normalizeTrustRoot(artifacts.trust.trustRoot) == TeeTrustRoot.GOOGLE -> TeeSignalLevel.PASS
        normalizeTrustRoot(artifacts.trust.trustRoot) == TeeTrustRoot.AOSP -> TeeSignalLevel.WARN
        else -> TeeSignalLevel.INFO
    }

    private fun rkpDisplayLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
        artifacts.rkp.provisioned && !artifacts.trust.chainSignatureValid -> TeeSignalLevel.FAIL
        artifacts.rkp.provisioned && hasLocalTrustReviewSignals(artifacts) -> TeeSignalLevel.WARN
        artifacts.rkp.provisioned -> TeeSignalLevel.PASS
        artifacts.rkp.consistencyIssue != null -> TeeSignalLevel.WARN
        else -> TeeSignalLevel.INFO
    }

    private fun crlSignalLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
        artifacts.crl.revokedCertificates.isNotEmpty() -> TeeSignalLevel.FAIL
        artifacts.crl.networkState.mode == TeeNetworkMode.ACTIVE -> TeeSignalLevel.PASS
        artifacts.crl.networkState.mode == TeeNetworkMode.ERROR -> TeeSignalLevel.WARN
        else -> TeeSignalLevel.INFO
    }

    private fun tierLevel(tier: TeeTier): TeeSignalLevel = when (tier) {
        TeeTier.STRONGBOX, TeeTier.TEE -> TeeSignalLevel.PASS
        TeeTier.SOFTWARE -> TeeSignalLevel.WARN
        TeeTier.NONE -> TeeSignalLevel.FAIL
        TeeTier.UNKNOWN -> TeeSignalLevel.INFO
    }

    private fun patchLevel(patchState: TeePatchState): TeeSignalLevel = when (patchState.grade) {
        TeePatchGrade.MATCHED -> TeeSignalLevel.PASS
        TeePatchGrade.WARNING, TeePatchGrade.SUSPICIOUS -> TeeSignalLevel.WARN
        TeePatchGrade.UNKNOWN -> TeeSignalLevel.INFO
    }

    private fun lifecycleLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
        artifacts.lifecycle.deleteRemovedAlias && artifacts.lifecycle.regeneratedFreshMaterial -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.FAIL
    }

    private fun keyboxLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
        !artifacts.keyboxImport.executed -> TeeSignalLevel.INFO
        artifacts.keyboxImport.markerPreserved -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.FAIL
    }

    private fun oversizedChallengeLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
        artifacts.oversizedChallenge.acceptedOversizedChallenge -> TeeSignalLevel.WARN
        else -> TeeSignalLevel.PASS
    }

    private fun generateModeAnomalyLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when (
        generateModeAnomalyState(artifacts)
    ) {
        GenerateModeAnomalyState.MATCHED -> TeeSignalLevel.FAIL
        GenerateModeAnomalyState.CLEAN -> TeeSignalLevel.PASS
        GenerateModeAnomalyState.UNAVAILABLE -> TeeSignalLevel.INFO
    }

    private fun timingSideChannelLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
        val skipSignature = timingSideChannelSkipSignature(artifacts.timingSideChannel)
        return when {
            skipSignature != null -> skipSignature.level
            !artifacts.timingSideChannel.probeRan -> TeeSignalLevel.INFO
            !artifacts.timingSideChannel.measurementAvailable -> TeeSignalLevel.INFO
            artifacts.timingSideChannel.suspicious -> TeeSignalLevel.WARN
            else -> TeeSignalLevel.INFO
        }
    }

    private fun timingSideChannelSkipSignature(
        result: TimingSideChannelResult,
    ): TimingSideChannelSkipSignature? {
        // 这里只识别 skip 场景：一旦 measurementAvailable=true，说明 timing probe 已经进入样本比较语义，不能再被静态栈特征改写成 patch-mode。
        // Only recognize skip scenarios here: once measurementAvailable=true, the probe is already in sample-comparison semantics and static stacks must not rewrite it into patch-mode.
        if (result.measurementAvailable) {
            return null
        }
        val payload = result.stackCopyPayload
            .replace("\r\n", "\n")
            .takeIf { it.isNotBlank() && it != "null" }
            ?: return null
        return when {
            // TEE Simulator 家族目前有两套稳定静态签名：
            // 1) tees-rs 样例里的 generateKey + deleteKey 组合；2) tees 样例里的 code -75 + legacy-db 组合。
            // timing 行仍然沿用 patch-mode 文案，生成模式结论则在 generateModeAnomalyState 里复用第二套组合。
            // The TEE Simulator family currently has two stable static signatures:
            // 1) the generateKey + deleteKey combination from the tees-rs sample; 2) the code -75 + legacy-db combination from the tees sample.
            // The timing row keeps the patch-mode wording, while generate-mode matching reuses the second combination in generateModeAnomalyState.
            payload.containsAllNeedles(
                listOf(
                    "android.os.ServiceSpecificException (code -49)",
                    "at android.os.Parcel.createExceptionOrNull",
                    "at android.os.Parcel.createException",
                    "at ${'$'}Proxy7.generateKey(Unknown Source)",
                    "Caused by:",
                    "0: Legacy database is empty.",
                    "1: Error::Rc(r#KEY_NOT_FOUND) (code 7)",
                    "at ${'$'}Proxy5.deleteKey(Unknown Source)",
                ),
            ) || payload.matchesTeeSimulatorLegacyDbSignature() -> TimingSideChannelSkipSignature.TEE_SIMULATOR_PATCH_MODE

            // 组合命中 ts 样例里的 getKeyEntry 失败栈后，再提升为 Tricky-Store Patch Mode。
            // Elevate to Tricky-Store Patch Mode only after the full getKeyEntry failure combination from the ts sample is present.
            payload.containsAllNeedles(
                listOf(
                    "Caused by: android.os.ServiceSpecificException (code 7)",
                    "at android.os.Parcel.createException",
                    "at android.os.Parcel.readException",
                    "at ${'$'}Proxy5.getKeyEntry(Unknown Source)",
                ),
            ) -> TimingSideChannelSkipSignature.TRICKY_STORE_PATCH_MODE

            // 如果所有更具体的 patch/generate 组合都没有命中，但仍然看到 Parcel 三连异常，就保留一个 warning 级别的私有 binder 兜底信号。
            // If no more specific patch/generate signature matches, keep a warning-level private-binder fallback when the Parcel exception trio is still present.
            payload.containsAllNeedles(
                listOf(
                    "at android.os.Parcel.createExceptionOrNull",
                    "at android.os.Parcel.createException",
                    "at android.os.Parcel.readException",
                ),
            ) -> TimingSideChannelSkipSignature.PRIVATE_BINDER_EXCEPTION

            else -> null
        }
    }

    private fun String.containsAllNeedles(needles: List<String>): Boolean {
        return needles.all { contains(it) }
    }

    private fun String.matchesTeeSimulatorLegacyDbSignature(): Boolean {
        return containsAllNeedles(
            listOf(
                "android.os.ServiceSpecificException (code -75)",
                "at android.os.Parcel.createExceptionOrNull",
                "at android.os.Parcel.createException",
                "at android.os.Parcel.readException",
                "Caused by:",
                "0: Legacy database is empty.",
                "1: Error::Rc(r#KEY_NOT_FOUND) (code 7)",
            ),
        )
    }

    private fun strongBoxLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
        artifacts.strongBox.hardFailures.isNotEmpty() -> TeeSignalLevel.WARN
        artifacts.strongBox.warnings.isNotEmpty() -> TeeSignalLevel.INFO
        artifacts.strongBox.available -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.INFO
    }

    private fun nativeSignalLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
        artifacts.native.trickyStoreDetected || artifacts.native.leafDerPrimaryDetected -> TeeSignalLevel.FAIL
        artifacts.native.leafDerSecondaryDetected || artifacts.native.tracingDetected || artifacts.native.suspiciousMappings.isNotEmpty() -> TeeSignalLevel.WARN
        artifacts.native.syscallMismatchDetected -> TeeSignalLevel.INFO
        else -> TeeSignalLevel.INFO
    }

    private fun soterLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
        artifacts.soter.damaged -> TeeSignalLevel.FAIL
        artifacts.soter.available -> TeeSignalLevel.PASS
        artifacts.soter.abnormalEnvironment -> TeeSignalLevel.WARN
        !artifacts.soter.serviceReachable -> TeeSignalLevel.WARN
        else -> TeeSignalLevel.INFO
    }

    private fun indicatorLevel(
        policyHardIndicators: List<TeeEvidenceItem>,
        policySoftIndicators: List<TeeEvidenceItem>,
        supplementaryIndicators: List<TeeEvidenceItem>,
    ): TeeSignalLevel = when {
        policyHardIndicators.isNotEmpty() -> TeeSignalLevel.FAIL
        policySoftIndicators.isNotEmpty() || supplementaryIndicators.isNotEmpty() -> TeeSignalLevel.WARN
        else -> TeeSignalLevel.PASS
    }

    private fun shortFingerprint(input: String?): String {
        if (input.isNullOrBlank()) {
            return "Unavailable"
        }
        return "${input.take(12)}..."
    }

    private fun generateModeAnomalyState(artifacts: TeeScanArtifacts): GenerateModeAnomalyState {
        val result = artifacts.generateModeParcelFingerprint
        val timingPayload = artifacts.timingSideChannel.stackCopyPayload
            .replace("\r\n", "\n")
            .takeIf { it.isNotBlank() && it != "null" }
        return when {
            result.matched -> GenerateModeAnomalyState.MATCHED
            // tees 样例里的 code -75 + legacy-db 组合落在 timing skip payload 里时，语义上也属于 TEE Simulator 生成链路命中。
            // When the tees code -75 + legacy-db combination lands in a timing skip payload, it also counts as a TEE Simulator generate-path hit.
            timingPayload?.matchesTeeSimulatorLegacyDbSignature() == true -> GenerateModeAnomalyState.MATCHED
            result.available -> GenerateModeAnomalyState.CLEAN
            else -> GenerateModeAnomalyState.UNAVAILABLE
        }
    }

    private fun indicatorValue(
        policyHardIndicators: List<TeeEvidenceItem>,
        policySoftIndicators: List<TeeEvidenceItem>,
        supplementaryIndicators: List<TeeEvidenceItem>,
    ): String {
        return "${policyHardIndicators.size} policy hard • " +
                "${policySoftIndicators.size} policy review • " +
                "${supplementaryIndicators.size} local"
    }

    private fun supplementaryReviewLevel(indicators: List<TeeEvidenceItem>): TeeSignalLevel = when {
        indicators.any { it.level == TeeSignalLevel.FAIL || it.level == TeeSignalLevel.WARN } ->
            TeeSignalLevel.WARN

        else -> TeeSignalLevel.INFO
    }

    private fun syscallMismatchExplanation(): String {
        return "Possible cause: vendor binder/libc compatibility differences. No stronger hook fingerprint was found."
    }

    private fun hasNativeReviewSignals(artifacts: TeeScanArtifacts): Boolean {
        return artifacts.native.syscallMismatchDetected ||
                artifacts.native.leafDerSecondaryDetected ||
                artifacts.native.tracingDetected ||
                artifacts.native.suspiciousMappings.isNotEmpty()
    }

    private fun nativeReviewSummary(artifacts: TeeScanArtifacts): String {
        return buildList {
            if (artifacts.native.syscallMismatchDetected) add("Syscall mismatch")
            if (artifacts.native.leafDerSecondaryDetected) add("Secondary DER hit")
            if (artifacts.native.tracingDetected) add("Tracing active")
            if (artifacts.native.suspiciousMappings.isNotEmpty()) {
                add("${artifacts.native.suspiciousMappings.size} suspicious mapping(s)")
            }
        }.joinToString(separator = " • ")
    }

    private fun nativeMethodSummary(artifacts: TeeScanArtifacts): String {
        val labels = artifacts.native.trickyStoreMethods
            .map(::prettyNativeMethod)
            .ifEmpty {
                buildList {
                    if (artifacts.native.gotHookDetected) add("GOT hook")
                    if (artifacts.native.inlineHookDetected) add("Inline hook")
                    if (artifacts.native.honeypotDetected) add("Honeypot")
                    if (artifacts.native.syscallMismatchDetected) add("Syscall mismatch")
                }
            }
        return labels.ifEmpty { listOf("TrickyStore") }.joinToString(separator = " • ")
    }

    private fun nativePrimarySignalLabel(artifacts: TeeScanArtifacts): String {
        return when {
            artifacts.native.gotHookDetected -> "GOT hook"
            artifacts.native.inlineHookDetected -> "Inline hook"
            artifacts.native.honeypotDetected -> "Honeypot"
            else -> nativeMethodSummary(artifacts)
        }
    }

    private fun prettyNativeMethod(method: String): String = when (method) {
        "MAPS_NAME_HIT" -> "Map hit"
        "GOT_HOOK" -> "GOT hook"
        "INLINE_HOOK" -> "Inline hook"
        "HONEYPOT" -> "Honeypot"
        "SYSCALL_MISMATCH" -> "Syscall mismatch"
        else -> method.replace('_', ' ').lowercase()
    }

    private fun trustRootLabel(trustRoot: TeeTrustRoot): String = when (trustRoot) {
        TeeTrustRoot.GOOGLE_RKP -> "Google root"
        TeeTrustRoot.GOOGLE -> "Google root"
        TeeTrustRoot.AOSP -> "AOSP root"
        TeeTrustRoot.FACTORY -> "Factory root"
        TeeTrustRoot.UNKNOWN -> "Unknown"
    }

    private fun normalizeTrustRoot(trustRoot: TeeTrustRoot): TeeTrustRoot = when (trustRoot) {
        TeeTrustRoot.GOOGLE_RKP -> TeeTrustRoot.GOOGLE
        else -> trustRoot
    }

    private fun localTrustChainLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
        artifacts.trust.chainLength == 0 -> TeeSignalLevel.INFO
        !artifacts.trust.chainSignatureValid -> TeeSignalLevel.FAIL
        hasLocalTrustReviewSignals(artifacts) -> TeeSignalLevel.WARN
        else -> TeeSignalLevel.PASS
    }

    private fun hasLocalTrustReviewSignals(artifacts: TeeScanArtifacts): Boolean {
        return artifacts.trust.expiredCertificates.isNotEmpty() || artifacts.trust.issuerMismatches.isNotEmpty()
    }

    private fun TeeTier.displayName(): String = when (this) {
        TeeTier.UNKNOWN -> "Unknown"
        TeeTier.NONE -> "None"
        TeeTier.SOFTWARE -> "Software"
        TeeTier.TEE -> "TEE"
        TeeTier.STRONGBOX -> "StrongBox"
    }

    private fun monthDistance(runtimePatch: String, attestedPatch: String): Int? {
        return runCatching {
            val runtime = parsePatchDate(runtimePatch)
            val attested = parsePatchDate(attestedPatch)
            if (runtime == null || attested == null) {
                null
            } else {
                val period = Period.between(runtime, attested)
                (period.years * 12 + period.months).absoluteValue
            }
        }.getOrNull()
    }

    private fun parsePatchDate(input: String): LocalDate? {
        val trimmed = input.trim()
        return when (trimmed.count { it == '-' }) {
            1 -> LocalDate.parse("$trimmed-01")
            2 -> LocalDate.parse(trimmed)
            else -> null
        }
    }
}
