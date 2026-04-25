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

import com.eltavine.duckdetector.features.tee.data.attestation.AttestationSnapshot
import com.eltavine.duckdetector.features.tee.data.native.NativeTeeSnapshot
import com.eltavine.duckdetector.features.tee.data.verification.boot.BootConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.certificate.ChainStructureResult
import com.eltavine.duckdetector.features.tee.data.verification.certificate.CertificateTrustResult
import com.eltavine.duckdetector.features.tee.data.verification.certificate.DualAlgorithmChainResult
import com.eltavine.duckdetector.features.tee.data.verification.crl.CrlStatusResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.IdAttestationResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderChainConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderHookBootstrapResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderPatchModeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BiometricTeeIntegrationResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GenerateModeParcelFingerprintResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.LegacyKeystorePathResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesBatchedResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataSemanticsResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataShapeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationErrorPathResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationPruningResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateSecurityLevelResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingSideChannelResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentResult
import com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorResult
import com.eltavine.duckdetector.features.tee.domain.TeeRkpState
import com.eltavine.duckdetector.features.tee.domain.TeeSoterState

data class TeeScanArtifacts(
    val snapshot: AttestationSnapshot,
    val trust: CertificateTrustResult,
    val chainStructure: ChainStructureResult,
    val rkp: TeeRkpState,
    val crl: CrlStatusResult,
    val pairConsistency: KeyPairConsistencyResult,
    val aesGcm: AesGcmRoundTripResult,
    val lifecycle: KeyLifecycleResult,
    val timing: TimingAnomalyResult,
    val timingSideChannel: TimingSideChannelResult,
    val oversizedChallenge: OversizedChallengeResult,
    val keyboxImport: KeyboxImportResult,
    val keystore2Hook: Keystore2HookResult,
    val generateModeParcelFingerprint: Keystore2GenerateModeParcelFingerprintResult,
    val legacyKeystorePath: LegacyKeystorePathResult,
    val listEntriesConsistency: ListEntriesConsistencyResult,
    val listEntriesBatched: ListEntriesBatchedResult,
    val keyMetadataSemantics: KeyMetadataSemanticsResult,
    val keyMetadataShape: KeyMetadataShapeResult,
    val pureCertificate: PureCertificateResult,
    val pureCertificateSecurityLevel: PureCertificateSecurityLevelResult,
    val operationErrorPath: OperationErrorPathResult,
    val biometricIntegration: BiometricTeeIntegrationResult,
    val binderHookBootstrap: BinderHookBootstrapResult,
    val binderPatchMode: BinderPatchModeResult,
    val binderChainConsistency: BinderChainConsistencyResult,
    val updateSubcomponent: UpdateSubcomponentResult,
    val pruning: OperationPruningResult,
    val dualAlgorithm: DualAlgorithmChainResult,
    val idAttestation: IdAttestationResult,
    val strongBox: StrongBoxBehaviorResult,
    val native: NativeTeeSnapshot,
    val soter: TeeSoterState,
    val bootConsistency: BootConsistencyResult,
)
