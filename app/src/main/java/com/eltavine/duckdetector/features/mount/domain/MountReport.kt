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

package com.eltavine.duckdetector.features.mount.domain

enum class MountStage {
    LOADING,
    READY,
    FAILED,
}

enum class MountFindingGroup {
    ARTIFACTS,
    RUNTIME,
    FILESYSTEM,
    CONSISTENCY,
}

enum class MountFindingSeverity {
    SAFE,
    WARNING,
    DANGER,
    INFO,
}

enum class MountMethodOutcome {
    CLEAN,
    WARNING,
    DANGER,
    SUPPORT,
}

data class MountFinding(
    val id: String,
    val label: String,
    val value: String,
    val group: MountFindingGroup,
    val severity: MountFindingSeverity,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class MountImpact(
    val text: String,
    val severity: MountFindingSeverity,
)

data class MountMethodResult(
    val label: String,
    val summary: String,
    val outcome: MountMethodOutcome,
    val detail: String? = null,
)

data class MountReport(
    val stage: MountStage,
    val nativeAvailable: Boolean,
    val mountsReadable: Boolean,
    val mountInfoReadable: Boolean,
    val mapsReadable: Boolean,
    val filesystemsReadable: Boolean,
    val initNamespaceReadable: Boolean,
    val statxSupported: Boolean,
    val permissionTotal: Int,
    val permissionDenied: Int,
    val permissionAccessible: Int,
    val mountEntryCount: Int,
    val mountInfoEntryCount: Int,
    val mapLineCount: Int,
    val earlyPreloadAvailable: Boolean,
    val earlyPreloadDetected: Boolean,
    val earlyPreloadContextValid: Boolean,
    val earlyPreloadFindingCount: Int,
    val findings: List<MountFinding>,
    val impacts: List<MountImpact>,
    val methods: List<MountMethodResult>,
    val errorMessage: String? = null,
) {
    val artifactRows: List<MountFinding>
        get() = findings.filter { it.group == MountFindingGroup.ARTIFACTS }

    val runtimeRows: List<MountFinding>
        get() = findings.filter { it.group == MountFindingGroup.RUNTIME }

    val filesystemRows: List<MountFinding>
        get() = findings.filter { it.group == MountFindingGroup.FILESYSTEM }

    val consistencyRows: List<MountFinding>
        get() = findings.filter { it.group == MountFindingGroup.CONSISTENCY }

    val dangerFindings: List<MountFinding>
        get() = findings.filter { it.severity == MountFindingSeverity.DANGER }

    val warningFindings: List<MountFinding>
        get() = findings.filter { it.severity == MountFindingSeverity.WARNING }

    companion object {
        fun loading(): MountReport {
            return MountReport(
                stage = MountStage.LOADING,
                nativeAvailable = true,
                mountsReadable = false,
                mountInfoReadable = false,
                mapsReadable = false,
                filesystemsReadable = false,
                initNamespaceReadable = false,
                statxSupported = false,
                permissionTotal = 0,
                permissionDenied = 0,
                permissionAccessible = 0,
                mountEntryCount = 0,
                mountInfoEntryCount = 0,
                mapLineCount = 0,
                earlyPreloadAvailable = false,
                earlyPreloadDetected = false,
                earlyPreloadContextValid = false,
                earlyPreloadFindingCount = 0,
                findings = emptyList(),
                impacts = emptyList(),
                methods = emptyList(),
            )
        }

        fun failed(message: String): MountReport {
            return MountReport(
                stage = MountStage.FAILED,
                nativeAvailable = false,
                mountsReadable = false,
                mountInfoReadable = false,
                mapsReadable = false,
                filesystemsReadable = false,
                initNamespaceReadable = false,
                statxSupported = false,
                permissionTotal = 0,
                permissionDenied = 0,
                permissionAccessible = 0,
                mountEntryCount = 0,
                mountInfoEntryCount = 0,
                mapLineCount = 0,
                earlyPreloadAvailable = false,
                earlyPreloadDetected = false,
                earlyPreloadContextValid = false,
                earlyPreloadFindingCount = 0,
                findings = emptyList(),
                impacts = emptyList(),
                methods = emptyList(),
                errorMessage = message,
            )
        }
    }
}
