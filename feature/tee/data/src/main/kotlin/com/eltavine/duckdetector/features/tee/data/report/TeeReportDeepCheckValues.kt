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

import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceItem
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceTopic

internal fun keyMetadataSemanticsValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.keyMetadataSemantics
    return when {
        !result.executed -> "Skipped"
        result.usesKeyIdDomain && result.aliasCleared -> "KEY_ID normalized"
        else -> "Descriptor mismatch"
    }
}

internal fun keyMetadataShapeValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.keyMetadataShape
    return when {
        !result.executed -> "Skipped"
        result.modificationTimeValid && result.hasOriginTag -> "System fields present"
        else -> "System fields missing"
    }
}

internal fun operationErrorPathValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.operationErrorPath
    if (!result.executed && result.probeError != null) return notRunValue(result.probeError)
    val status = when {
        !result.executed -> "Skipped"
        result.oversizedUpdateRejected == false -> "Oversized update accepted"
        result.abortInvalidatedHandle == false -> "Abort left operation alive"
        result.updateAadUnexpectedlyAccepted -> "updateAad accepted on a signing operation"
        result.fallbackCompatParamsUsed -> "Compatibility params required"
        result.subChecksIncomplete -> "Partially evaluated"
        else -> "Native-style errors"
    }
    val detail = result.detail.takeIf { it.isNotBlank() } ?: return status
    return "$status • $detail"
}

internal fun pruningValue(artifacts: TeeScanArtifacts): String {
    return if (artifacts.pruning.operationsCreated == 0) {
        "Skipped"
    } else {
        "${artifacts.pruning.invalidatedOperations}/${artifacts.pruning.operationsCreated} invalidated"
    }
}

internal fun dualAlgorithmValue(artifacts: TeeScanArtifacts): String {
    return if (!artifacts.dualAlgorithm.executed) {
        notRunValue(artifacts.dualAlgorithm.probeError)
    } else if (artifacts.dualAlgorithm.mismatchDetected) {
        "RSA/EC chain difference observed"
    } else {
        "RSA/EC chains aligned"
    }
}

internal fun idAttestationValue(artifacts: TeeScanArtifacts): String {
    return when {
        !artifacts.idAttestation.probeRan -> "Skipped"
        artifacts.idAttestation.mismatches.isNotEmpty() -> "${artifacts.idAttestation.mismatches.size} mismatch(es)"
        artifacts.idAttestation.unavailableFields.size >= 5 -> "No comparable IDs exposed"
        artifacts.idAttestation.unavailableFields.isNotEmpty() -> "${artifacts.idAttestation.unavailableFields.size} comparable field(s) not exposed"
        else -> "Available fields aligned"
    }
}

internal fun biometricIntegrationValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.biometricIntegration
    return when {
        !result.executed -> "Skipped"
        !result.strongBiometricAvailable -> "Strong biometric unavailable"
        result.keyCreated && result.keyRetrieved -> "User-auth key path available"
        result.keyCreated -> "Created but getKey() returned null"
        else -> "User-auth key path failed"
    }
}

internal fun strongBoxFact(artifacts: TeeScanArtifacts): TeeEvidenceItem = fact(
    "StrongBox",
    strongBoxValue(artifacts),
    strongBoxLevel(artifacts),
    hiddenCopyText = artifacts.strongBox.binderObservation?.let { binder ->
        listOf(binder.detail, artifacts.strongBox.keyInfoUnavailableDetail)
            .filter(String::isNotBlank)
            .joinToString("\n")
    },
    topic = TeeEvidenceTopic.STRONGBOX,
)

internal fun strongBoxValue(artifacts: TeeScanArtifacts): String {
    val strongBox = artifacts.strongBox
    val binder = strongBox.binderObservation
    val binderFailure = binder?.takeIf { it.failed }?.let {
        if (strongBox.available && !it.missingSystemFeature) {
            "A StrongBox key was observed. The Keystore2 query also failed during this scan."
        } else {
            it.summary
        }
    }
    strongBox.hardFailures.firstOrNull()?.let { failure ->
        return listOfNotNull(failure, binderFailure).joinToString(" • ")
    }

    val state = when {
        binderFailure != null -> binderFailure
        strongBox.available -> buildString {
            append("Available")
            strongBox.keyInfoLevel?.let {
                append(" • ")
                append(it)
            }
        }
        // "Not confirmed" covers both a key that came back without StrongBox backing and a probe
        // that never got an answer. Only the first is evidence about the device, so name the
        // reason whenever the probe recorded one.
        strongBox.requested -> buildString {
            append("Not confirmed")
            strongBox.keyInfoUnavailableDetail.takeIf(String::isNotBlank)?.let {
                append(" • ")
                append(it)
            }
        }

        binder != null -> binder.summary
        !strongBox.advertised -> "Not advertised"
        else -> "Skipped"
    }
    // Warnings follow the state instead of replacing it. They are INFO-level notes here, and a
    // working StrongBox that signed quickly is still a working StrongBox, so leading with the
    // note used to hide both availability and the reported key level. All of them are kept
    // because showing only the first dropped the rest.
    return (listOf(state) + strongBox.warnings).joinToString(" • ")
}

internal fun listEntriesConsistencyValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.listEntriesConsistency
    return when {
        !result.executed -> "Skipped"
        result.badParcelableLikeCrash -> "BadParcelable-style crash"
        result.inconsistent -> "containsAlias/listEntries mismatch"
        else -> "containsAlias and aliases aligned"
    }
}

internal fun listEntriesBatchedValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.listEntriesBatched
    return when {
        !result.executed -> "Skipped"
        result.cursorEchoed -> "Cursor echoed in page"
        result.expectedNextMissing -> "Expected next alias missing"
        else -> "Cursor semantics aligned"
    }
}
