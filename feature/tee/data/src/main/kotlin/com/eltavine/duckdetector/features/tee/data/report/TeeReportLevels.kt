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

package com.eltavine.duckdetector.features.tee.data.report

import com.eltavine.duckdetector.capability.attestation.data.AttestationSnapshot
import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import com.eltavine.duckdetector.capability.attestation.domain.TeeTrustRoot
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2PostProcessingAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SupplementaryAttestationInfoAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.rkp.RkpProvisionedManufacturerAnomalyKind
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceItem
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkMode
import com.eltavine.duckdetector.features.tee.domain.TeePatchGrade
import com.eltavine.duckdetector.features.tee.domain.TeePatchState
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel

internal fun pureCertificateTopLevelSecurityLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.pureCertificateSecurityLevel
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.securityLevelPresent -> TeeSignalLevel.FAIL
        else -> TeeSignalLevel.PASS
    }
}

internal fun pureCertificateMetadataSecurityLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.pureCertificateSecurityLevel
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.metadataSecurityLevelPresent -> TeeSignalLevel.INFO
        else -> TeeSignalLevel.PASS
    }
}

internal fun chainLayoutLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    artifacts.chainStructure.provisioningConsistencyIssue -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.INFO
}

internal fun challengeLevel(snapshot: AttestationSnapshot): TeeSignalLevel = when {
    snapshot.trustedAttestationIndex == null -> TeeSignalLevel.INFO
    snapshot.challengeVerified -> TeeSignalLevel.PASS
    else -> TeeSignalLevel.FAIL
}

internal fun verifiedBootLevel(snapshot: AttestationSnapshot): TeeSignalLevel {
    val bootState = snapshot.rootOfTrust?.verifiedBootState ?: return TeeSignalLevel.INFO
    return if (bootState == "Verified") TeeSignalLevel.PASS else TeeSignalLevel.WARN
}

internal fun bootSignalLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val root = artifacts.snapshot.rootOfTrust
    return when {
        artifacts.bootConsistency.hasHardAnomaly -> TeeSignalLevel.FAIL
        root == null -> TeeSignalLevel.INFO
        !artifacts.bootConsistency.runtimePropsAvailable -> TeeSignalLevel.INFO
        artifacts.bootConsistency.runtimeComparisonPerformed -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.INFO
    }
}

internal fun deviceInfoLevel(snapshot: AttestationSnapshot): TeeSignalLevel {
    return if (snapshot.deviceInfo.asDisplayMap()
            .isEmpty()
    ) TeeSignalLevel.INFO else TeeSignalLevel.PASS
}

internal fun trustLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    !artifacts.trust.chainSignatureValid -> TeeSignalLevel.FAIL
    hasLocalTrustReviewSignals(artifacts) -> TeeSignalLevel.WARN
    normalizeTrustRoot(artifacts.trust.trustRoot) == TeeTrustRoot.GOOGLE -> TeeSignalLevel.PASS
    normalizeTrustRoot(artifacts.trust.trustRoot) == TeeTrustRoot.AOSP -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.INFO
}

internal fun rkpDisplayLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    artifacts.rkp.provisioned && !artifacts.trust.chainSignatureValid -> TeeSignalLevel.FAIL
    artifacts.rkp.provisioned && hasLocalTrustReviewSignals(artifacts) -> TeeSignalLevel.WARN
    artifacts.rkp.provisioned -> TeeSignalLevel.PASS
    artifacts.rkp.consistencyIssue != null -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.INFO
}

internal fun crlSignalLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    hasHardRevocation(artifacts) -> TeeSignalLevel.FAIL
    hasLocalMassAbuseRevocation(artifacts) -> TeeSignalLevel.WARN
    artifacts.crl.networkState.mode == TeeNetworkMode.ACTIVE -> TeeSignalLevel.PASS
    artifacts.crl.networkState.mode == TeeNetworkMode.ERROR -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.INFO
}

internal fun tierLevel(tier: TeeTier): TeeSignalLevel = when (tier) {
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

internal fun pureCertificateLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    !artifacts.pureCertificate.executed -> TeeSignalLevel.INFO
    artifacts.pureCertificate.pureCertificateReturnsNullKey -> TeeSignalLevel.PASS
    else -> TeeSignalLevel.FAIL
}

internal fun supplementaryAttestationInfoLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when (
    artifacts.supplementaryAttestationInfo.anomalyKind
) {
    SupplementaryAttestationInfoAnomalyKind.MISSING_ATTESTATION_MODULE_HASH,
    SupplementaryAttestationInfoAnomalyKind.MISMATCH,
    SupplementaryAttestationInfoAnomalyKind.UNEXPECTED_ATTESTATION_MODULE_HASH -> TeeSignalLevel.WARN
    SupplementaryAttestationInfoAnomalyKind.NONE -> TeeSignalLevel.PASS
    SupplementaryAttestationInfoAnomalyKind.UNSUPPORTED -> TeeSignalLevel.INFO
}

internal fun vintfKeyMintVersionLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when (
    artifacts.vintfKeyMintVersion.anomalyKind
) {
    VintfKeyMintVersionAnomalyKind.MISMATCH -> TeeSignalLevel.FAIL
    VintfKeyMintVersionAnomalyKind.NONE -> TeeSignalLevel.PASS
    VintfKeyMintVersionAnomalyKind.UNREADABLE,
    VintfKeyMintVersionAnomalyKind.NO_DECLARATION,
    VintfKeyMintVersionAnomalyKind.NO_ATTESTED_VERSION -> TeeSignalLevel.INFO
}

internal fun postProcessingLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when (
    artifacts.postProcessing.anomalyKind
) {
    Keystore2PostProcessingAnomalyKind.ROOT_OF_TRUST_DIVERGENCE,
    Keystore2PostProcessingAnomalyKind.TIMING_DETECTED -> TeeSignalLevel.FAIL
    Keystore2PostProcessingAnomalyKind.TIMING_SUSPECT -> TeeSignalLevel.WARN
    Keystore2PostProcessingAnomalyKind.NONE -> TeeSignalLevel.PASS
    // 这三种都是"测不了"，不能当成通过 / These three all mean "could not test" and must not read as a pass
    Keystore2PostProcessingAnomalyKind.RKP_UNAVAILABLE,
    Keystore2PostProcessingAnomalyKind.RKP_FALLBACK_INCONCLUSIVE,
    Keystore2PostProcessingAnomalyKind.UNMEASURABLE -> TeeSignalLevel.INFO
}

internal fun rkpProvisionedManufacturerLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when (
    artifacts.rkpProvisionedManufacturer.anomalyKind
) {
    RkpProvisionedManufacturerAnomalyKind.MISMATCH -> TeeSignalLevel.FAIL
    RkpProvisionedManufacturerAnomalyKind.NONE -> TeeSignalLevel.PASS
    RkpProvisionedManufacturerAnomalyKind.PARTIALLY_EVALUATED,
    RkpProvisionedManufacturerAnomalyKind.UNAVAILABLE -> TeeSignalLevel.INFO
}

internal fun indicatorLevel(
    policyHardIndicators: List<TeeEvidenceItem>,
    policySoftIndicators: List<TeeEvidenceItem>,
    supplementaryIndicators: List<TeeEvidenceItem>,
): TeeSignalLevel = when {
    policyHardIndicators.isNotEmpty() -> TeeSignalLevel.FAIL
    supplementaryIndicators.any { it.level == TeeSignalLevel.FAIL } -> TeeSignalLevel.FAIL
    policySoftIndicators.isNotEmpty() ||
        supplementaryIndicators.any { it.level == TeeSignalLevel.WARN } -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.PASS
}

internal fun supplementaryReviewLevel(indicators: List<TeeEvidenceItem>): TeeSignalLevel = when {
    // Report aggregation is severity-first: a later FAIL must still outrank an earlier WARN.
    // Report 聚合按严重级别优先：后出现的 FAIL 必须压过先出现的 WARN。
    indicators.any { it.level == TeeSignalLevel.FAIL } -> TeeSignalLevel.FAIL
    indicators.any { it.level == TeeSignalLevel.WARN } -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.INFO
}

internal fun localTrustChainLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    artifacts.trust.chainLength == 0 -> TeeSignalLevel.INFO
    !artifacts.trust.chainSignatureValid -> TeeSignalLevel.FAIL
    hasLocalTrustReviewSignals(artifacts) -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.PASS
}
