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

package com.eltavine.duckdetector.features.bootloader.domain

import com.eltavine.duckdetector.features.tee.domain.TeeTier
import com.eltavine.duckdetector.features.tee.domain.TeeTrustRoot

enum class BootloaderStage {
    LOADING,
    READY,
    FAILED,
}

enum class BootloaderState {
    VERIFIED,
    SELF_SIGNED,
    UNLOCKED,
    FAILED_VERIFICATION,
    LOCKED_UNKNOWN,
    UNKNOWN,
}

enum class BootloaderEvidenceMode {
    ATTESTATION,
    PROPERTIES_ONLY,
    UNAVAILABLE,
}

enum class BootloaderFindingGroup {
    STATE,
    ATTESTATION,
    PROPERTIES,
    CONSISTENCY,
}

enum class BootloaderFindingSeverity {
    SAFE,
    WARNING,
    DANGER,
    INFO,
}

enum class BootloaderMethodOutcome {
    CLEAN,
    WARNING,
    DANGER,
    SUPPORT,
}

data class BootloaderFinding(
    val id: String,
    val label: String,
    val value: String,
    val group: BootloaderFindingGroup,
    val severity: BootloaderFindingSeverity,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class BootloaderImpact(
    val text: String,
    val severity: BootloaderFindingSeverity,
)

data class BootloaderMethodResult(
    val label: String,
    val summary: String,
    val outcome: BootloaderMethodOutcome,
    val detail: String? = null,
)

data class BootloaderReport(
    val stage: BootloaderStage,
    val state: BootloaderState,
    val evidenceMode: BootloaderEvidenceMode,
    val trustRoot: TeeTrustRoot,
    val tier: TeeTier,
    val attestationAvailable: Boolean,
    val hardwareBacked: Boolean,
    val attestationChainLength: Int,
    val checkedPropertyCount: Int,
    val observedPropertyCount: Int,
    val nativePropertyHitCount: Int,
    val rawBootParamHitCount: Int,
    val sourceMismatchCount: Int,
    val consistencyFindingCount: Int,
    val findings: List<BootloaderFinding>,
    val impacts: List<BootloaderImpact>,
    val methods: List<BootloaderMethodResult>,
    val errorMessage: String? = null,
) {
    val dangerFindings: List<BootloaderFinding>
        get() = findings.filter { it.severity == BootloaderFindingSeverity.DANGER }

    val warningFindings: List<BootloaderFinding>
        get() = findings.filter { it.severity == BootloaderFindingSeverity.WARNING }

    val stateRows: List<BootloaderFinding>
        get() = findings.filter { it.group == BootloaderFindingGroup.STATE }

    val attestationRows: List<BootloaderFinding>
        get() = findings.filter { it.group == BootloaderFindingGroup.ATTESTATION }

    val propertyRows: List<BootloaderFinding>
        get() = findings.filter { it.group == BootloaderFindingGroup.PROPERTIES }

    val consistencyRows: List<BootloaderFinding>
        get() = findings.filter { it.group == BootloaderFindingGroup.CONSISTENCY }

    companion object {
        fun loading(): BootloaderReport {
            return BootloaderReport(
                stage = BootloaderStage.LOADING,
                state = BootloaderState.UNKNOWN,
                evidenceMode = BootloaderEvidenceMode.UNAVAILABLE,
                trustRoot = TeeTrustRoot.UNKNOWN,
                tier = TeeTier.UNKNOWN,
                attestationAvailable = false,
                hardwareBacked = false,
                attestationChainLength = 0,
                checkedPropertyCount = 0,
                observedPropertyCount = 0,
                nativePropertyHitCount = 0,
                rawBootParamHitCount = 0,
                sourceMismatchCount = 0,
                consistencyFindingCount = 0,
                findings = emptyList(),
                impacts = emptyList(),
                methods = emptyList(),
            )
        }

        fun failed(message: String): BootloaderReport {
            return BootloaderReport(
                stage = BootloaderStage.FAILED,
                state = BootloaderState.UNKNOWN,
                evidenceMode = BootloaderEvidenceMode.UNAVAILABLE,
                trustRoot = TeeTrustRoot.UNKNOWN,
                tier = TeeTier.UNKNOWN,
                attestationAvailable = false,
                hardwareBacked = false,
                attestationChainLength = 0,
                checkedPropertyCount = 0,
                observedPropertyCount = 0,
                nativePropertyHitCount = 0,
                rawBootParamHitCount = 0,
                sourceMismatchCount = 0,
                consistencyFindingCount = 0,
                findings = emptyList(),
                impacts = emptyList(),
                methods = emptyList(),
                errorMessage = message,
            )
        }
    }
}
