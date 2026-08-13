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

package com.eltavine.duckdetector.features.tee.data.repository

import android.content.Context
import android.os.Build
import com.eltavine.duckdetector.features.tee.data.attestation.AndroidAttestationCollector
import com.eltavine.duckdetector.features.tee.data.native.TeeNativeBridge
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkConsentStore
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefsStore
import com.eltavine.duckdetector.features.tee.data.report.TeeReportReducer
import com.eltavine.duckdetector.features.tee.data.report.TeeScanArtifacts
import com.eltavine.duckdetector.features.tee.data.soter.SoterCapabilityProbe
import com.eltavine.duckdetector.features.tee.data.verification.boot.BootConsistencyProbe
import com.eltavine.duckdetector.features.tee.data.verification.certificate.CertificateTrustAnalyzer
import com.eltavine.duckdetector.features.tee.data.verification.certificate.ChainStructureAnalyzer
import com.eltavine.duckdetector.features.tee.data.verification.certificate.DualAlgorithmChainProbe
import com.eltavine.duckdetector.features.tee.data.verification.certificate.GoogleAttestationRootStore
import com.eltavine.duckdetector.features.tee.data.verification.crl.CrlStatusService
import com.eltavine.duckdetector.features.tee.data.verification.keystore.IdAttestationProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderChainConsistencyProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderHookBootstrapProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderPatchModeProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BiometricTeeIntegrationProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ImportKeyRetainedAttestationNarrativeProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMintCapabilityProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataSemanticsProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataShapeProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GenerateModeParcelFingerprintProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainFullChainSplitProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainFullChainSplitResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainFullChainSplitProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainFullChainSplitResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGetKeyEntryAccessVectorBlindnessProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.LegacyKeystorePathProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesBatchedProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesConsistencyProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationErrorPathProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationPruningProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateSecurityLevelProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SupplementaryAttestationInfoProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingSideChannelProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentStaleResponsePersistenceProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2PostProcessingProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2PostProcessingResult
import com.eltavine.duckdetector.features.tee.data.verification.rkp.RkpProvisionedManufacturerProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionFamily
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionResult
import com.eltavine.duckdetector.features.tee.data.verification.rkp.RkpExtensionAnalyzer
import com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorProbeSuite
import com.eltavine.duckdetector.features.tee.domain.TeeReport
import com.eltavine.duckdetector.features.tee.domain.TeeSoterState
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext

class TeeRepository(
    context: Context,
    private val collector: AndroidAttestationCollector = AndroidAttestationCollector(),
    private val nativeBridge: TeeNativeBridge = TeeNativeBridge(),
    private val reducer: TeeReportReducer = TeeReportReducer(),
) {

    private val appContext = context.applicationContext
    private val consentStore: TeeNetworkPrefsStore = TeeNetworkConsentStore.getInstance(appContext)
    private val bootConsistencyProbe = BootConsistencyProbe()
    private val trustAnalyzer = CertificateTrustAnalyzer(GoogleAttestationRootStore(appContext))
    private val chainStructureAnalyzer = ChainStructureAnalyzer()
    private val rkpAnalyzer = RkpExtensionAnalyzer()
    private val crlStatusService = CrlStatusService(appContext, consentStore)
    private val pairConsistencyProbe = KeyPairConsistencyProbe()
    private val aesGcmProbe = AesGcmRoundTripProbe()
    private val lifecycleProbe = KeyLifecycleProbe()
    private val keyMintCapabilityProbe = KeyMintCapabilityProbe()
    private val timingProbe = TimingAnomalyProbe()
    private val timingSideChannelProbe = TimingSideChannelProbe()
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
    private val supplementaryAttestationInfoProbe = SupplementaryAttestationInfoProbe(appContext)
    private val vintfKeyMintVersionProbe = VintfKeyMintVersionProbe()
    private val postProcessingProbe = Keystore2PostProcessingProbe()
    private val rkpProvisionedManufacturerProbe = RkpProvisionedManufacturerProbe()
    private val strongBoxProbe = StrongBoxBehaviorProbeSuite(appContext, collector)
    private val soterProbe = SoterCapabilityProbe(appContext)

    suspend fun scan(): TeeReport = withContext(Dispatchers.Default) {
        runCatching {
            val snapshot = collector.collect(useStrongBox = false)
            val trust = trustAnalyzer.inspect(snapshot.rawCertificates)
            val chainStructure = chainStructureAnalyzer.inspect(snapshot.rawCertificates)
            val rkp = rkpAnalyzer.analyze(
                snapshot.rawCertificates,
                chainStructure,
                trust.googleRootMatched
            )
            val crl = crlStatusService.inspect(snapshot.rawCertificates)
            val native =
                nativeBridge.collectSnapshot(snapshot.rawCertificates.firstOrNull()?.encoded)
            val soter = runCatching { soterProbe.inspect() }.getOrDefault(TeeSoterState())
            val bootConsistency = bootConsistencyProbe.inspect(snapshot)
            val supplementaryAttestationInfo = supplementaryAttestationInfoProbe.inspect(snapshot)
            val vintfKeyMintVersion = vintfKeyMintVersionProbe.inspect(snapshot)
            // 这条探针要成对生成带 attestation 的 key，代价明显，因此只在硬件 KeyMint 层级下运行
            // This probe generates attested keys pairwise and is visibly expensive, so it only runs on a hardware KeyMint tier.
            // keystore2 的 RkpdProvisioned 分支从 Android 15 起才有 process_certificate_chain 调用点
            // keystore2's RkpdProvisioned arm has no process_certificate_chain call site before Android 15
            val postProcessing = if (Build.VERSION.SDK_INT < 35) {
                Keystore2PostProcessingResult(
                    probeRan = false,
                    detail = "Skipped because keystore2 has no certificate post-processing call site below Android 15.",
                )
            } else if (snapshot.tier == TeeTier.TEE || snapshot.tier == TeeTier.STRONGBOX) {
                runCatching {
                    postProcessingProbe.inspect(useStrongBox = snapshot.tier == TeeTier.STRONGBOX)
                }.getOrElse {
                    Keystore2PostProcessingResult(
                        probeRan = false,
                        detail = "Keystore2 post-processing probe failed to start: ${it.message ?: it::class.java.simpleName}",
                    )
                }
            } else {
                Keystore2PostProcessingResult(
                    probeRan = false,
                    detail = "Skipped because the device did not expose a hardware-backed KeyMint tier.",
                )
            }
            val timingSideChannel = timingSideChannelProbe.inspect(
                useStrongBox = false,
                nativeSnapshot = native,
            )
            val deepChecks = collectDeepChecks(
                useStrongBox = snapshot.tier == TeeTier.STRONGBOX,
                deepChecksAllowed = snapshot.tier == TeeTier.TEE || snapshot.tier == TeeTier.STRONGBOX,
                snapshot = snapshot,
                vintfKeyMintVersion = vintfKeyMintVersion,
                timingSideChannel = timingSideChannel,
            )


            reducer.reduce(
                TeeScanArtifacts(
                    snapshot = snapshot,
                    trust = trust,
                    chainStructure = chainStructure,
                    rkp = rkp,
                    crl = crl,
                    pairConsistency = deepChecks.pairConsistency,
                    aesGcm = deepChecks.aesGcm,
                    lifecycle = deepChecks.lifecycle,
                    keyMintCapability = deepChecks.keyMintCapability,
                    timing = deepChecks.timing,
                    timingSideChannel = deepChecks.timingSideChannel,
                    oversizedChallenge = deepChecks.oversizedChallenge,
                    keyboxImport = deepChecks.keyboxImport,
                    importKeyRetainedAttestationNarrative = deepChecks.importKeyRetainedAttestationNarrative,
                    supplementaryAttestationInfo = supplementaryAttestationInfo,
                    vintfKeyMintVersion = vintfKeyMintVersion,
                    keystore2Hook = deepChecks.keystore2Hook,
                    generateModeParcelFingerprint = deepChecks.generateModeParcelFingerprint,
                    postProcessing = postProcessing,
                    rkpProvisionedManufacturer = rkpProvisionedManufacturerProbe.inspect(rkp, snapshot),
                    grantDomainFullChainSplit = deepChecks.grantDomainFullChainSplit,
                    syntheticGrantGranteeBlindReadback = deepChecks.syntheticGrantGranteeBlindReadback,
                    syntheticGrantGetKeyEntryAccessVectorBlindness =
                        deepChecks.syntheticGrantGetKeyEntryAccessVectorBlindness,
                    grantSelfDomainFullChainSplit = deepChecks.grantSelfDomainFullChainSplit,
                    legacyKeystorePath = deepChecks.legacyKeystorePath,
                    listEntriesConsistency = deepChecks.listEntriesConsistency,
                    listEntriesBatched = deepChecks.listEntriesBatched,
                    keyMetadataSemantics = deepChecks.keyMetadataSemantics,
                    keyMetadataShape = deepChecks.keyMetadataShape,
                    pureCertificate = deepChecks.pureCertificate,
                    pureCertificateSecurityLevel = deepChecks.pureCertificateSecurityLevel,
                    operationErrorPath = deepChecks.operationErrorPath,
                    biometricIntegration = deepChecks.biometricIntegration,
                    binderHookBootstrap = deepChecks.binderHookBootstrap,
                    binderPatchMode = deepChecks.binderPatchMode,
                    binderChainConsistency = deepChecks.binderChainConsistency,
                    updateSubcomponent = deepChecks.updateSubcomponent,
                    updateSubcomponentStaleResponsePersistence =
                        deepChecks.updateSubcomponentStaleResponsePersistence,
                    pruning = deepChecks.pruning,
                    dualAlgorithm = deepChecks.dualAlgorithm,
                    idAttestation = deepChecks.idAttestation,
                    strongBox = deepChecks.strongBox,
                    native = native,
                    soter = soter,
                    bootConsistency = bootConsistency,
                ),
            )
        }.getOrElse { throwable ->
            TeeReport.failed(throwable.message ?: "TEE scan failed.")
        }
    }

    private suspend fun collectDeepChecks(
        useStrongBox: Boolean,
        deepChecksAllowed: Boolean,
        snapshot: com.eltavine.duckdetector.features.tee.data.attestation.AttestationSnapshot,
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
        val strongBox = async { strongBoxProbe.inspect() }
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

internal fun keyMintRuntimeIdentityConsistent(
    attestationVersion: Int?,
    keymasterVersion: Int?,
): Boolean {
    if (attestationVersion == null || keymasterVersion == null) {
        return true
    }
    val attestationIsKeyMint = attestationVersion >= KEYMINT_VERSION_FAMILY_BASE
    val keymasterIsKeyMint = keymasterVersion >= KEYMINT_VERSION_FAMILY_BASE
    if (attestationIsKeyMint != keymasterIsKeyMint) {
        return false
    }
    if (attestationIsKeyMint) {
        return attestationVersion == keymasterVersion
    }
    // keymasterVersion keeps the legacy Keymaster encoding (2, 3, 4, 41).
    // attestationVersion is a separate attestation-record semantic (1, 2, 3, 4);
    // this table is an AOSP-defined cross-field relationship, not linear arithmetic.
    // keymasterVersion 保留旧 Keymaster 编码（2、3、4、41），attestationVersion 是独立的
    // attestation record 语义（1、2、3、4）；这里是 AOSP 定义的跨字段映射，不是线性换算。
    //
    // AOSP references:
    // system/keymaster/include/keymaster/km_openssl/attestation_record.h
    // https://android.googlesource.com/platform/system/keymaster/+/refs/heads/main/include/keymaster/km_openssl/attestation_record.h
    // hardware/interfaces/keymaster/4.0/vts/functional/keymaster_hidl_hal_test.cpp
    // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/keymaster/4.0/vts/functional/keymaster_hidl_hal_test.cpp
    return LEGACY_KEYMASTER_TO_ATTESTATION_VERSION[keymasterVersion] == attestationVersion
}

private const val KEYMINT_VERSION_FAMILY_BASE = 100
private val LEGACY_KEYMASTER_TO_ATTESTATION_VERSION = mapOf(
    2 to 1,
    3 to 2,
    4 to 3,
    41 to 4,
)

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

private data class DeferredChecks(
    val pairConsistency: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyResult,
    val aesGcm: com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripResult,
    val lifecycle: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleResult,
    val keyMintCapability: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMintCapabilityResult,
    val timing: com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyResult,
    val timingSideChannel: com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingSideChannelResult,
    val oversizedChallenge: com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeResult,
    val keyboxImport: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportResult,
    val importKeyRetainedAttestationNarrative: com.eltavine.duckdetector.features.tee.data.verification.keystore.ImportKeyRetainedAttestationNarrativeResult,
    val keystore2Hook: com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookResult,
    val generateModeParcelFingerprint: com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GenerateModeParcelFingerprintResult,
    val grantDomainFullChainSplit: com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainFullChainSplitResult,
    val syntheticGrantGranteeBlindReadback: com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackResult,
    val syntheticGrantGetKeyEntryAccessVectorBlindness: com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGetKeyEntryAccessVectorBlindnessResult,
    val grantSelfDomainFullChainSplit: com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainFullChainSplitResult,
    val legacyKeystorePath: com.eltavine.duckdetector.features.tee.data.verification.keystore.LegacyKeystorePathResult,
    val listEntriesConsistency: com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesConsistencyResult,
    val listEntriesBatched: com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesBatchedResult,
    val keyMetadataSemantics: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataSemanticsResult,
    val keyMetadataShape: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataShapeResult,
    val pureCertificate: com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateResult,
    val pureCertificateSecurityLevel: com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateSecurityLevelResult,
    val operationErrorPath: com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationErrorPathResult,
    val biometricIntegration: com.eltavine.duckdetector.features.tee.data.verification.keystore.BiometricTeeIntegrationResult,
    val binderHookBootstrap: com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderHookBootstrapResult,
    val binderPatchMode: com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderPatchModeResult,
    val binderChainConsistency: com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderChainConsistencyResult,
    val updateSubcomponent: com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentResult,
    val updateSubcomponentStaleResponsePersistence: com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentStaleResponsePersistenceResult,
    val pruning: com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationPruningResult,
    val dualAlgorithm: com.eltavine.duckdetector.features.tee.data.verification.certificate.DualAlgorithmChainResult,
    val idAttestation: com.eltavine.duckdetector.features.tee.data.verification.keystore.IdAttestationResult,
    val strongBox: com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorResult,
) {
    companion object {
        fun skipped(
            snapshot: com.eltavine.duckdetector.features.tee.data.attestation.AttestationSnapshot,
            timingSideChannel: com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingSideChannelResult,
        ) = DeferredChecks(
            pairConsistency = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyResult(
                keyMatchesCertificate = true,
                detail = "Deep checks were skipped because hardware-backed attestation was not established.",
            ),
            aesGcm = com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripResult(
                executed = false,
                detail = "AES-GCM round-trip probe skipped.",
            ),
            lifecycle = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleResult(
                created = false,
                deleteRemovedAlias = true,
                regeneratedFreshMaterial = true,
                detail = "Lifecycle probe skipped.",
            ),
            keyMintCapability = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMintCapabilityResult(
                executed = false,
            ),
            timing = com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyResult(
                suspicious = false,
                detail = "Timing probe skipped.",
            ),
            timingSideChannel = timingSideChannel,

            oversizedChallenge = com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeResult(
                acceptedOversizedChallenge = false,
                acceptedSizes = emptyList(),
                attemptedSizes = com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeProbe.CHALLENGE_SIZES,
                detail = "Oversized challenge probe skipped.",
            ),
            keyboxImport = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportResult(
                executed = false,
                markerPreserved = true,
                marker = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportProbe.FIXTURE_MARKER,
                detail = "Keybox import probe skipped.",
            ),
            importKeyRetainedAttestationNarrative = com.eltavine.duckdetector.features.tee.data.verification.keystore.ImportKeyRetainedAttestationNarrativeResult(
                executed = false,
                detail = "ImportKey retained attestation narrative probe skipped.",
            ),
            keystore2Hook = com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookResult(
                available = false,
                detail = "Keystore2 hook probe skipped.",
            ),
            generateModeParcelFingerprint = com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GenerateModeParcelFingerprintResult(
                executed = false,
                detail = "Keystore2 generate-mode parcel fingerprint probe skipped.",
            ),
            grantDomainFullChainSplit = com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainFullChainSplitResult(
                detail = "Grant-domain full-chain split probe skipped.",
            ),
            syntheticGrantGranteeBlindReadback = com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackResult(
                detail = "Grant caller-binding private binder probe skipped.",
            ),
            syntheticGrantGetKeyEntryAccessVectorBlindness =
                com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                    detail = "Grant access-vector private binder probe skipped.",
                ),
            grantSelfDomainFullChainSplit = com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainFullChainSplitResult(
                detail = "Grant self-domain full-chain split probe skipped.",
            ),
            legacyKeystorePath = com.eltavine.duckdetector.features.tee.data.verification.keystore.LegacyKeystorePathResult(
                executed = false,
                detail = "Legacy keystore path probe skipped.",
            ),
            listEntriesConsistency = com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesConsistencyResult(
                executed = false,
                detail = "listEntries consistency probe skipped.",
            ),
            listEntriesBatched = com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesBatchedResult(
                executed = false,
                detail = "listEntriesBatched probe skipped.",
            ),
            keyMetadataSemantics = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataSemanticsResult(
                executed = false,
                detail = "KeyMetadata semantics probe skipped.",
            ),
            keyMetadataShape = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataShapeResult(
                executed = false,
                detail = "KeyMetadata shape probe skipped.",
            ),
            pureCertificate = com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateResult(
                pureCertificateReturnsNullKey = true,
                detail = "Pure certificate probe skipped.",
            ),
            pureCertificateSecurityLevel = com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateSecurityLevelResult(
                executed = false,
                detail = "Pure certificate security-level probe skipped.",
            ),
            operationErrorPath = com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationErrorPathResult(
                executed = false,
                detail = "Operation error-path probe skipped.",
            ),
            biometricIntegration = com.eltavine.duckdetector.features.tee.data.verification.keystore.BiometricTeeIntegrationResult(
                executed = false,
                detail = "Biometric TEE integration probe skipped.",
            ),
            binderHookBootstrap = com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderHookBootstrapResult(
                executed = false,
                detail = "Binder hook bootstrap probe skipped.",
            ),
            binderPatchMode = com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderPatchModeResult(
                executed = false,
                detail = "Binder patch-mode probe skipped.",
            ),
            binderChainConsistency = com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderChainConsistencyResult(
                executed = false,
                detail = "Binder chain consistency probe skipped.",
            ),
            updateSubcomponent = com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentResult(
                updateSucceeded = true,
                keyNotFoundStyleFailure = false,
                detail = "Update subcomponent probe skipped.",
            ),
            updateSubcomponentStaleResponsePersistence =
                com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentStaleResponsePersistenceResult(
                    detail = "UpdateSubcomponent stale response persistence probe skipped.",
                ),
            pruning = com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationPruningResult(
                suspicious = false,
                operationsCreated = 0,
                invalidatedOperations = 0,
                detail = "Pruning probe skipped.",
            ),
            dualAlgorithm = com.eltavine.duckdetector.features.tee.data.verification.certificate.DualAlgorithmChainResult(
                mismatchDetected = false,
                detail = "Dual algorithm comparison skipped.",
            ),
            idAttestation = com.eltavine.duckdetector.features.tee.data.verification.keystore.IdAttestationResult(
                mismatches = emptyList(),
                unavailableFields = emptyList(),
                detail = "ID attestation probe skipped.",
                probeRan = false,
            ),
            strongBox = com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorResult(
                requested = false,
                advertised = false,
                available = false,
                detail = "StrongBox probe skipped.",
            ),
        )
    }
}
