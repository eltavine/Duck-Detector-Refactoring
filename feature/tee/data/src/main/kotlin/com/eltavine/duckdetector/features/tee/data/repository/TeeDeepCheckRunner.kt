/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.features.tee.data.repository

import android.content.Context
import com.eltavine.duckdetector.capability.attestation.data.AndroidAttestationCollector
import com.eltavine.duckdetector.capability.attestation.data.CertificateTrustAnalyzer
import com.eltavine.duckdetector.features.tee.data.verification.certificate.DualAlgorithmChainProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderChainConsistencyProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderHookBootstrapProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderPatchModeProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BiometricTeeIntegrationProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainFullChainSplitProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainFullChainSplitResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainFullChainSplitProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainFullChainSplitResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.IdAttestationProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ImportKeyRetainedAttestationNarrativeProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataSemanticsProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataShapeProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMintCapabilityProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GenerateModeParcelFingerprintProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.LegacyKeystorePathProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesBatchedProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesConsistencyProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationErrorPathProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationPruningProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateSecurityLevelProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGetKeyEntryAccessVectorBlindnessProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentStaleResponsePersistenceProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionFamily
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionResult
import com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorProbeSuite
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

/**
 * The keystore deep checks of a TEE scan: every probe that exercises keystore2 and KeyMint beyond
 * the attestation record, run concurrently when the scan allows them.
 */
internal class TeeDeepCheckRunner(
    private val appContext: Context,
    private val collector: AndroidAttestationCollector,
    private val trustAnalyzer: CertificateTrustAnalyzer,
) {
    private val pairConsistencyProbe = KeyPairConsistencyProbe()
    private val aesGcmProbe = AesGcmRoundTripProbe()
    private val lifecycleProbe = KeyLifecycleProbe()
    private val keyMintCapabilityProbe = KeyMintCapabilityProbe()
    private val timingProbe = TimingAnomalyProbe()
    private val oversizedChallengeProbe = OversizedChallengeProbe()
    private val keyboxImportProbe = KeyboxImportProbe(appContext)
    private val importKeyRetainedAttestationNarrativeProbe =
        ImportKeyRetainedAttestationNarrativeProbe(appContext)
    private val keystore2HookProbe = Keystore2HookProbe()
    private val generateModeParcelFingerprintProbe = Keystore2GenerateModeParcelFingerprintProbe()
    private val grantDomainFullChainSplitProbe = GrantDomainFullChainSplitProbe(appContext)
    private val grantSelfDomainFullChainSplitProbe = GrantSelfDomainFullChainSplitProbe(appContext)
    private val syntheticGrantGranteeBlindReadbackProbe = SyntheticGrantGranteeBlindReadbackProbe(appContext)
    private val syntheticGrantGetKeyEntryAccessVectorBlindnessProbe =
        SyntheticGrantGetKeyEntryAccessVectorBlindnessProbe(appContext)
    private val legacyKeystorePathProbe = LegacyKeystorePathProbe()
    private val listEntriesConsistencyProbe = ListEntriesConsistencyProbe()
    private val listEntriesBatchedProbe = ListEntriesBatchedProbe()
    private val keyMetadataSemanticsProbe = KeyMetadataSemanticsProbe()
    private val keyMetadataShapeProbe = KeyMetadataShapeProbe()
    private val pureCertificateProbe = PureCertificateProbe()
    private val pureCertificateSecurityLevelProbe = PureCertificateSecurityLevelProbe()
    private val operationErrorPathProbe = OperationErrorPathProbe()
    private val biometricIntegrationProbe = BiometricTeeIntegrationProbe(appContext)
    private val binderHookBootstrapProbe = BinderHookBootstrapProbe()
    private val binderPatchModeProbe = BinderPatchModeProbe()
    private val binderChainConsistencyProbe = BinderChainConsistencyProbe()
    private val updateSubcomponentProbe = UpdateSubcomponentProbe()
    private val updateSubcomponentStaleResponsePersistenceProbe =
        UpdateSubcomponentStaleResponsePersistenceProbe(appContext)
    private val operationPruningProbe = OperationPruningProbe()
    private val dualAlgorithmProbe = DualAlgorithmChainProbe(trustAnalyzer)
    private val idAttestationProbe = IdAttestationProbe()
    private val strongBoxProbe = StrongBoxBehaviorProbeSuite(collector)

    suspend fun collect(
        useStrongBox: Boolean,
        deepChecksAllowed: Boolean,
        strongBoxAdvertised: Boolean,
        snapshot: com.eltavine.duckdetector.capability.attestation.data.AttestationSnapshot,
        vintfKeyMintVersion: VintfKeyMintVersionResult,
        timingSideChannel: com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingSideChannelResult,
    ): DeferredChecks = coroutineScope {
        if (!deepChecksAllowed) {
            return@coroutineScope DeferredChecks.skipped(snapshot, timingSideChannel)
        }

        val pairConsistency = async { pairConsistencyProbe.inspect(useStrongBox = useStrongBox) }
        val aesGcm = async { aesGcmProbe.inspect(useStrongBox = useStrongBox) }
        val lifecycle = async { lifecycleProbe.inspect(useStrongBox = useStrongBox) }
        val keyMintCapability = async {
            // KeyMint operations are obtained from one explicit IKeystoreSecurityLevel (TEE or
            // StrongBox). If the attestation record names different security levels for the two
            // version fields, testing either binder instance would test the wrong identity.
            // KeyMint 操作来自一个明确的 IKeystoreSecurityLevel（TEE 或 StrongBox）。如果
            // attestation record 的两个版本字段属于不同 security level，选择任一 binder
            // 实例都会测错对象，因此 MGF1 子探针必须 skip，由独立一致性证据报 FAIL。
            //
            // AOSP references:
            // system/hardware/interfaces/keystore2/aidl/android/system/keystore2/IKeystoreService.aidl
            // https://android.googlesource.com/platform/system/hardware/interfaces/+/refs/heads/main/keystore2/aidl/android/system/keystore2/IKeystoreService.aidl
            // system/hardware/interfaces/keystore2/aidl/android/system/keystore2/IKeystoreSecurityLevel.aidl
            // https://android.googlesource.com/platform/system/hardware/interfaces/+/refs/heads/main/keystore2/aidl/android/system/keystore2/IKeystoreSecurityLevel.aidl
            val tierConsistent = snapshot.attestationTier == null || snapshot.keymasterTier == null ||
                snapshot.attestationTier == snapshot.keymasterTier
            val nativeKeyMintObserved = listOfNotNull(snapshot.attestationVersion, snapshot.keymasterVersion)
                .any { it >= 100 }
            // AIDL KeyMint projects both attestation fields from the same interface version, while
            // legacy Keymaster uses the explicit 2->1, 3->2, 4->3, 41->4 mapping below.
            // AIDL KeyMint 的两个 attestation 字段来自同一个接口版本；legacy Keymaster 则使用
            // 下方 AOSP 明确定义的 2->1、3->2、4->3、41->4 映射。
            val runtimeIdentityConsistent = keyMintRuntimeIdentityConsistent(
                attestationVersion = snapshot.attestationVersion,
                keymasterVersion = snapshot.keymasterVersion,
            )
            keyMintCapabilityProbe.inspect(
                attestationVersion = snapshot.attestationVersion,
                keymasterVersion = snapshot.keymasterVersion,
                declaredKeyMintVersion = vintfKeyMintVersion.declarations
                    .filter {
                        it.family == VintfKeyMintVersionFamily.KEYMINT_AIDL &&
                            it.instance == if (useStrongBox) "strongbox" else "default"
                    }
                    .maxOfOrNull { it.expectedKeymasterVersion },
                legacyKeymasterDeclared = !nativeKeyMintObserved && vintfKeyMintVersion.declarations.none {
                    it.family == VintfKeyMintVersionFamily.KEYMINT_AIDL &&
                        it.instance == if (useStrongBox) "strongbox" else "default"
                } && vintfKeyMintVersion.declarations.any {
                    it.family == VintfKeyMintVersionFamily.KEYMASTER_HIDL &&
                        it.instance == if (useStrongBox) "strongbox" else "default"
                },
                securityLevelsConsistent = tierConsistent,
                runtimeIdentityConsistent = runtimeIdentityConsistent,
                useStrongBox = useStrongBox,
            )
        }
        val timing = async { timingProbe.inspect(useStrongBox = useStrongBox) }
        val oversizedChallenge = async { oversizedChallengeProbe.inspect(useStrongBox = useStrongBox) }
        val keyboxImport = async { keyboxImportProbe.inspect() }
        // Run after keybox import fixtures are available, but keep it independent so unsupported importKey paths degrade to INFO only.
        // 放在 keybox import fixture 可用之后独立执行；importKey 不可观测时只降级为 INFO，不影响主扫描。
        val importKeyRetainedAttestationNarrative = async {
            importKeyRetainedAttestationNarrativeProbe.inspect()
        }
        val keystore2Hook = async { keystore2HookProbe.inspect() }
        val listEntriesConsistency = async { listEntriesConsistencyProbe.inspect() }
        val listEntriesBatched = async { listEntriesBatchedProbe.inspect() }
        val keyMetadataSemantics = async { keyMetadataSemanticsProbe.inspect() }
        val keyMetadataShape = async { keyMetadataShapeProbe.inspect() }
        val pureCertificate = async { pureCertificateProbe.inspect() }
        val pureCertificateSecurityLevel = async { pureCertificateSecurityLevelProbe.inspect() }
        val operationErrorPath = async { operationErrorPathProbe.inspect() }
        val biometricIntegration = async { biometricIntegrationProbe.inspect() }
        val updateSubcomponent = async { updateSubcomponentProbe.inspect(useStrongBox = useStrongBox) }
        val pruning = async { operationPruningProbe.inspect(useStrongBox = useStrongBox) }
        val dualAlgorithm = async {
            val comparison = collector.collectComparisonChains(useStrongBox = useStrongBox)
            dualAlgorithmProbe.inspect(comparison.first, comparison.second)
        }
        val idAttestation = async { idAttestationProbe.inspect(snapshot) }
        val strongBox = async { strongBoxProbe.inspect(strongBoxAdvertised) }
        val pairConsistencyResult = pairConsistency.await()
        val aesGcmResult = aesGcm.await()
        val lifecycleResult = lifecycle.await()
        val keyMintCapabilityResult = keyMintCapability.await()
        val timingResult = timing.await()
        val oversizedChallengeResult = oversizedChallenge.await()
        val keyboxImportResult = keyboxImport.await()
        val importKeyRetainedAttestationNarrativeResult = importKeyRetainedAttestationNarrative.await()
        val keystore2HookResult = keystore2Hook.await()
        val listEntriesConsistencyResult = listEntriesConsistency.await()
        val listEntriesBatchedResult = listEntriesBatched.await()
        val keyMetadataSemanticsResult = keyMetadataSemantics.await()
        val keyMetadataShapeResult = keyMetadataShape.await()
        val pureCertificateResult = pureCertificate.await()
        val pureCertificateSecurityLevelResult = pureCertificateSecurityLevel.await()
        val operationErrorPathResult = operationErrorPath.await()
        val biometricIntegrationResult = biometricIntegration.await()
        val updateSubcomponentResult = updateSubcomponent.await()
        val pruningResult = pruning.await()
        val dualAlgorithmResult = dualAlgorithm.await()
        val idAttestationResult = idAttestation.await()
        val strongBoxResult = strongBox.await()

        val generateModeParcelFingerprint = generateModeParcelFingerprintProbe.inspect()
        val grantDomainFullChainSplit = grantDomainFullChainSplitProbe.inspect(useStrongBox = useStrongBox)
        val grantSelfDomainFullChainSplit = grantSelfDomainFullChainSplitProbe.inspect(useStrongBox = useStrongBox)
        val syntheticGrantGranteeBlindReadback =
            if (grantDomainFullChainSplit.hasDanger() || grantSelfDomainFullChainSplit.hasDanger()) {
                SyntheticGrantGranteeBlindReadbackProbe.skippedAfterExistingGrantDanger()
            } else {
                syntheticGrantGranteeBlindReadbackProbe.inspect(useStrongBox = useStrongBox)
            }
        val syntheticGrantGetKeyEntryAccessVectorBlindness =
            if (
                grantDomainFullChainSplit.hasDanger() ||
                grantSelfDomainFullChainSplit.hasDanger() ||
                syntheticGrantGranteeBlindReadback.hasDanger()
            ) {
                SyntheticGrantGetKeyEntryAccessVectorBlindnessProbe.skippedAfterExistingGrantDanger()
            } else {
                syntheticGrantGetKeyEntryAccessVectorBlindnessProbe.inspect(useStrongBox = useStrongBox)
            }
        val legacyKeystorePath = legacyKeystorePathProbe.inspect()
        val binderHookBootstrap = binderHookBootstrapProbe.inspect()
        val binderPatchMode = binderPatchModeProbe.inspect()
        val binderChainConsistency = binderChainConsistencyProbe.inspect()
        // Run after the basic update failure probe: this one judges successful KEY_ID update persistence, not update failure itself.
        // 放在基础 update 失败探针之后：此探针判断成功 KEY_ID update 后的持久叙事，而不是 update 失败本身。
        val updateSubcomponentStaleResponsePersistence =
            updateSubcomponentStaleResponsePersistenceProbe.inspect(useStrongBox = useStrongBox)

        DeferredChecks(
            pairConsistency = pairConsistencyResult,
            aesGcm = aesGcmResult,
            lifecycle = lifecycleResult,
            keyMintCapability = keyMintCapabilityResult,
            timing = timingResult,
            timingSideChannel = timingSideChannel,
            oversizedChallenge = oversizedChallengeResult,
            keyboxImport = keyboxImportResult,
            importKeyRetainedAttestationNarrative = importKeyRetainedAttestationNarrativeResult,
            keystore2Hook = keystore2HookResult,
            generateModeParcelFingerprint = generateModeParcelFingerprint,
            grantDomainFullChainSplit = grantDomainFullChainSplit,
            syntheticGrantGranteeBlindReadback = syntheticGrantGranteeBlindReadback,
            syntheticGrantGetKeyEntryAccessVectorBlindness = syntheticGrantGetKeyEntryAccessVectorBlindness,
            grantSelfDomainFullChainSplit = grantSelfDomainFullChainSplit,
            legacyKeystorePath = legacyKeystorePath,
            listEntriesConsistency = listEntriesConsistencyResult,
            listEntriesBatched = listEntriesBatchedResult,
            keyMetadataSemantics = keyMetadataSemanticsResult,
            keyMetadataShape = keyMetadataShapeResult,
            pureCertificate = pureCertificateResult,
            pureCertificateSecurityLevel = pureCertificateSecurityLevelResult,
            operationErrorPath = operationErrorPathResult,
            biometricIntegration = biometricIntegrationResult,
            binderHookBootstrap = binderHookBootstrap,
            binderPatchMode = binderPatchMode,
            binderChainConsistency = binderChainConsistency,
            updateSubcomponent = updateSubcomponentResult,
            updateSubcomponentStaleResponsePersistence = updateSubcomponentStaleResponsePersistence,
            pruning = pruningResult,
            dualAlgorithm = dualAlgorithmResult,
            idAttestation = idAttestationResult,
            strongBox = strongBoxResult,
        )
    }
}

private fun GrantDomainFullChainSplitResult.hasDanger(): Boolean {
    return anomalyKind == GrantDomainAnomalyKind.ISOLATED_CHAIN_SPLIT ||
        anomalyKind == GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN
}

private fun GrantSelfDomainFullChainSplitResult.hasDanger(): Boolean {
    return anomalyKind == GrantSelfDomainAnomalyKind.SELF_CHAIN_SPLIT ||
        anomalyKind == GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN ||
        anomalyKind == GrantSelfDomainAnomalyKind.SELF_GRANT_ATTESTATION_APP_KEY_NOT_FOUND
}

private fun SyntheticGrantGranteeBlindReadbackResult.hasDanger(): Boolean {
    return anomalyKind == SyntheticGrantGranteeBlindReadbackAnomalyKind.NON_GRANTEE_READBACK_ALLOWED
}
