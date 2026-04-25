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
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataSemanticsProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataShapeProbe
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
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingSideChannelProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentProbe
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
    private val timingProbe = TimingAnomalyProbe()
    private val timingSideChannelProbe = TimingSideChannelProbe()
    private val oversizedChallengeProbe = OversizedChallengeProbe()
    private val keyboxImportProbe = KeyboxImportProbe(appContext)
    private val keystore2HookProbe = Keystore2HookProbe()
    private val generateModeParcelFingerprintProbe = Keystore2GenerateModeParcelFingerprintProbe()
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
    private val operationPruningProbe = OperationPruningProbe()
    private val dualAlgorithmProbe = DualAlgorithmChainProbe(trustAnalyzer)
    private val idAttestationProbe = IdAttestationProbe()
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
            val timingSideChannel = timingSideChannelProbe.inspect(
                useStrongBox = false,
                nativeSnapshot = native,
            )
            val deepChecks = collectDeepChecks(
                useStrongBox = snapshot.tier == TeeTier.STRONGBOX,
                deepChecksAllowed = snapshot.tier == TeeTier.TEE || snapshot.tier == TeeTier.STRONGBOX,
                snapshot = snapshot,
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
                    timing = deepChecks.timing,
                    timingSideChannel = deepChecks.timingSideChannel,
                    oversizedChallenge = deepChecks.oversizedChallenge,
                    keyboxImport = deepChecks.keyboxImport,
                    keystore2Hook = deepChecks.keystore2Hook,
                    generateModeParcelFingerprint = deepChecks.generateModeParcelFingerprint,
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
        timingSideChannel: com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingSideChannelResult,
    ): DeferredChecks = coroutineScope {
        if (!deepChecksAllowed) {
            return@coroutineScope DeferredChecks.skipped(snapshot, timingSideChannel)
        }

        val pairConsistency = async { pairConsistencyProbe.inspect(useStrongBox = useStrongBox) }
        val aesGcm = async { aesGcmProbe.inspect(useStrongBox = useStrongBox) }
        val lifecycle = async { lifecycleProbe.inspect(useStrongBox = useStrongBox) }
        val timing = async { timingProbe.inspect(useStrongBox = useStrongBox) }
        val oversizedChallenge = async { oversizedChallengeProbe.inspect(useStrongBox = useStrongBox) }
        val keyboxImport = async { keyboxImportProbe.inspect() }
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
        val timingResult = timing.await()
        val oversizedChallengeResult = oversizedChallenge.await()
        val keyboxImportResult = keyboxImport.await()
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
        val legacyKeystorePath = legacyKeystorePathProbe.inspect()
        val binderHookBootstrap = binderHookBootstrapProbe.inspect()
        val binderPatchMode = binderPatchModeProbe.inspect()
        val binderChainConsistency = binderChainConsistencyProbe.inspect()

        DeferredChecks(
            pairConsistency = pairConsistencyResult,
            aesGcm = aesGcmResult,
            lifecycle = lifecycleResult,
            timing = timingResult,
            timingSideChannel = timingSideChannel,
            oversizedChallenge = oversizedChallengeResult,
            keyboxImport = keyboxImportResult,
            keystore2Hook = keystore2HookResult,
            generateModeParcelFingerprint = generateModeParcelFingerprint,
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
            pruning = pruningResult,
            dualAlgorithm = dualAlgorithmResult,
            idAttestation = idAttestationResult,
            strongBox = strongBoxResult,
        )
    }

}

private data class DeferredChecks(
    val pairConsistency: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyResult,
    val aesGcm: com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripResult,
    val lifecycle: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleResult,
    val timing: com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyResult,
    val timingSideChannel: com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingSideChannelResult,
    val oversizedChallenge: com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeResult,
    val keyboxImport: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportResult,
    val keystore2Hook: com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookResult,
    val generateModeParcelFingerprint: com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GenerateModeParcelFingerprintResult,
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
            keystore2Hook = com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookResult(
                available = false,
                detail = "Keystore2 hook probe skipped.",
            ),
            generateModeParcelFingerprint = com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GenerateModeParcelFingerprintResult(
                executed = false,
                detail = "Keystore2 generate-mode parcel fingerprint probe skipped.",
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
