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

import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentStaleResponseAnomalyKind
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel

internal fun aesGcmLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    return when {
        !artifacts.aesGcm.executed -> TeeSignalLevel.INFO
        !artifacts.aesGcm.roundTripSucceeded -> TeeSignalLevel.FAIL
        aesGcmAuthorizationFailures(artifacts.aesGcm).isNotEmpty() -> TeeSignalLevel.FAIL
        artifacts.aesGcm.insideSecureHardware == false -> TeeSignalLevel.WARN
        !artifacts.aesGcm.authorizationChecked -> TeeSignalLevel.INFO
        else -> TeeSignalLevel.PASS
    }
}

internal fun listEntriesConsistencyLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.listEntriesConsistency
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.badParcelableLikeCrash || result.inconsistent -> TeeSignalLevel.FAIL
        else -> TeeSignalLevel.PASS
    }
}

internal fun listEntriesBatchedLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.listEntriesBatched
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.cursorEchoed -> TeeSignalLevel.FAIL
        result.expectedNextMissing -> TeeSignalLevel.WARN
        else -> TeeSignalLevel.PASS
    }
}

internal fun keyMetadataSemanticsLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.keyMetadataSemantics
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.usesKeyIdDomain && result.aliasCleared -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.FAIL
    }
}

internal fun importKeyRetainedAttestationNarrativeLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.importKeyRetainedAttestationNarrative
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.retainedNarrativeDetected -> TeeSignalLevel.FAIL
        result.importSupported && result.markerImportBaselineClean -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.INFO
    }
}

internal fun grantDomainFullChainSplitLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.grantDomainFullChainSplit
    return when {
        // These anomaly kinds are already curated by the probe, so reducer can safely upgrade them without parsing detail text.
        // 这些 anomaly kind 已由 probe 结构化归类，reducer 不需要解析 detail 文本即可升级。
        result.anomalyKind == GrantDomainAnomalyKind.ISOLATED_CHAIN_SPLIT -> TeeSignalLevel.FAIL
        result.anomalyKind == GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN ->
            TeeSignalLevel.FAIL
        result.anomalyKind == GrantDomainAnomalyKind.ISOLATED_PRIVATE_READBACK_CRASH -> TeeSignalLevel.WARN

        result.executed && result.splitDetected -> TeeSignalLevel.FAIL
        result.executed && result.available -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.INFO
    }
}

internal fun syntheticGrantGranteeBlindReadbackLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.syntheticGrantGranteeBlindReadback
    return when (result.anomalyKind) {
        SyntheticGrantGranteeBlindReadbackAnomalyKind.NON_GRANTEE_READBACK_ALLOWED -> TeeSignalLevel.FAIL
        SyntheticGrantGranteeBlindReadbackAnomalyKind.NONE ->
            if (result.executed && result.available) TeeSignalLevel.PASS else TeeSignalLevel.INFO
        SyntheticGrantGranteeBlindReadbackAnomalyKind.SKIPPED_AFTER_EXISTING_GRANT_DANGER,
        SyntheticGrantGranteeBlindReadbackAnomalyKind.UNAVAILABLE -> TeeSignalLevel.INFO
    }
}

internal fun syntheticGrantGetKeyEntryAccessVectorBlindnessLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.syntheticGrantGetKeyEntryAccessVectorBlindness
    return when (result.anomalyKind) {
        SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.GET_KEY_ENTRY_WITHOUT_GET_INFO_ALLOWED ->
            TeeSignalLevel.FAIL
        SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.NONE ->
            if (result.executed && result.available) TeeSignalLevel.PASS else TeeSignalLevel.INFO
        SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.SKIPPED_AFTER_EXISTING_GRANT_DANGER,
        SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.UNAVAILABLE -> TeeSignalLevel.INFO
    }
}

internal fun grantSelfDomainFullChainSplitLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.grantSelfDomainFullChainSplit
    return when {
        // Same-UID key-not-found is not ordinary unavailability: the owner alias was proven readable before grant.
        // 同 UID key-not-found 不是普通不可用：grant 之前 owner alias 已被证明可读。
        result.anomalyKind == GrantSelfDomainAnomalyKind.SELF_CHAIN_SPLIT ||
            result.anomalyKind == GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN ||
            result.anomalyKind == GrantSelfDomainAnomalyKind.SELF_GRANT_ATTESTATION_APP_KEY_NOT_FOUND -> {
            TeeSignalLevel.FAIL
        }
        result.executed && result.available -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.INFO
    }
}

internal fun updateSubcomponentStaleResponsePersistenceLevel(
    artifacts: TeeScanArtifacts,
): TeeSignalLevel {
    val result = artifacts.updateSubcomponentStaleResponsePersistence
    return when (result.anomalyKind) {
        UpdateSubcomponentStaleResponseAnomalyKind.STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE ->
            TeeSignalLevel.FAIL

        UpdateSubcomponentStaleResponseAnomalyKind.NONE -> TeeSignalLevel.PASS
        UpdateSubcomponentStaleResponseAnomalyKind.UPDATE_SUBCOMPONENT_UNOBSERVABLE,
        UpdateSubcomponentStaleResponseAnomalyKind.UPDATE_FAILED,
        UpdateSubcomponentStaleResponseAnomalyKind.UNAVAILABLE -> TeeSignalLevel.INFO
    }
}

internal fun keyMetadataShapeLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.keyMetadataShape
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.modificationTimeValid && result.hasOriginTag -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.FAIL
    }
}

internal fun operationErrorPathLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.operationErrorPath
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.keystore2SemanticsDiverged -> TeeSignalLevel.FAIL
        result.updateAadUnexpectedlyAccepted || result.fallbackCompatParamsUsed -> TeeSignalLevel.WARN
        result.subChecksIncomplete -> TeeSignalLevel.INFO
        else -> TeeSignalLevel.PASS
    }
}

internal fun biometricIntegrationLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.biometricIntegration
    return when {
        !result.executed -> TeeSignalLevel.INFO
        !result.strongBiometricAvailable -> TeeSignalLevel.INFO
        result.keyCreated && result.keyRetrieved -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.FAIL
    }
}

internal fun binderChainConsistencyLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
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

internal fun binderHookBootstrapLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.binderHookBootstrap
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.hookInstalled -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.FAIL
    }
}

internal fun legacyKeystorePathLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.legacyKeystorePath
    return when {
        !result.executed -> TeeSignalLevel.INFO
        !result.hookInstalled -> TeeSignalLevel.INFO
        !result.legacyMaterialAvailable -> TeeSignalLevel.INFO
        result.chainMatches -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.WARN
    }
}

internal fun binderPatchModeLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.binderPatchMode
    return when {
        !result.executed -> TeeSignalLevel.INFO
        !result.hookInstalled -> TeeSignalLevel.FAIL
        result.leafDiffers || result.chainDiffers -> TeeSignalLevel.FAIL
        result.generateMaterialAvailable && result.keyEntryMaterialAvailable -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.INFO
    }
}

internal fun keyPairLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    !artifacts.pairConsistency.executed -> TeeSignalLevel.INFO
    artifacts.pairConsistency.keyMatchesCertificate -> TeeSignalLevel.PASS
    else -> TeeSignalLevel.FAIL
}

internal fun lifecycleLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    !artifacts.lifecycle.executed -> TeeSignalLevel.INFO
    artifacts.lifecycle.deleteRemovedAlias && artifacts.lifecycle.regeneratedFreshMaterial -> TeeSignalLevel.PASS
    else -> TeeSignalLevel.FAIL
}

internal fun keyboxLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    !artifacts.keyboxImport.executed -> TeeSignalLevel.INFO
    artifacts.keyboxImport.markerPreserved -> TeeSignalLevel.PASS
    else -> TeeSignalLevel.FAIL
}

internal fun oversizedChallengeLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    !artifacts.oversizedChallenge.executed -> TeeSignalLevel.INFO
    artifacts.oversizedChallenge.acceptedOversizedChallenge -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.PASS
}

internal fun generateModeAnomalyLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when (
    generateModeAnomalyState(artifacts)
) {
    GenerateModeAnomalyState.MATCHED -> TeeSignalLevel.FAIL
    GenerateModeAnomalyState.REVIEW -> TeeSignalLevel.WARN
    GenerateModeAnomalyState.CLEAN -> TeeSignalLevel.PASS
    GenerateModeAnomalyState.UNAVAILABLE -> TeeSignalLevel.INFO
}

internal fun timingSideChannelLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val skipSignature = timingSideChannelSkipSignature(artifacts.timingSideChannel)
    return when {
        skipSignature != null -> skipSignature.level
        !artifacts.timingSideChannel.probeRan -> TeeSignalLevel.INFO
        !artifacts.timingSideChannel.measurementAvailable -> TeeSignalLevel.INFO
        !artifacts.timingSideChannel.ratioEligible -> TeeSignalLevel.INFO
        artifacts.timingSideChannel.suspicious -> TeeSignalLevel.WARN
        else -> TeeSignalLevel.INFO
    }
}

internal fun strongBoxLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    artifacts.strongBox.hardFailures.isNotEmpty() -> TeeSignalLevel.WARN
    artifacts.strongBox.warnings.isNotEmpty() -> TeeSignalLevel.INFO
    artifacts.strongBox.available -> TeeSignalLevel.PASS
    else -> TeeSignalLevel.INFO
}

internal fun soterLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    artifacts.soter.damaged -> TeeSignalLevel.FAIL
    artifacts.soter.anomalies.isNotEmpty() -> TeeSignalLevel.WARN
    artifacts.soter.available -> TeeSignalLevel.PASS
    artifacts.soter.abnormalEnvironment -> TeeSignalLevel.WARN
    !artifacts.soter.serviceReachable -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.INFO
}
