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

enum class MountZygoteNextState {
    PENDING,
    UNSUPPORTED,
    UNAVAILABLE,
    READY,
}

enum class MountZygoteNextNamespaceAssessment {
    INIT_MANAGED,
    UNVERIFIED,
}

data class MountZygoteNextMarker(
    val labels: List<String>,
    val mountPoint: String,
    val mountRoot: String,
    val fileSystemType: String,
    val source: String,
    val rawLine: String,
) {
    val dangerous: Boolean
        get() = labels.any { it != DEBUG_RAMDISK_LABEL }

    companion object {
        private const val DEBUG_RAMDISK_LABEL = "debug_ramdisk"
    }
}

data class MountZygoteNextReport(
    val state: MountZygoteNextState,
    val sdkInt: Int,
    val mainNamespaceInode: Long = 0L,
    val mainPropagation: String = "",
    val mainRootMountId: Long = 0L,
    val mainMinimumMountId: Long = 0L,
    val mainMaximumMountId: Long = 0L,
    val mainMountCount: Int = 0,
    val mainMarkers: List<MountZygoteNextMarker> = emptyList(),
    val isolatedNamespaceInode: Long = 0L,
    val isolatedPropagation: String = "",
    val isolatedRootMountId: Long = 0L,
    val isolatedMinimumMountId: Long = 0L,
    val isolatedMaximumMountId: Long = 0L,
    val isolatedMountCount: Int = 0,
    val isolatedMarkers: List<MountZygoteNextMarker> = emptyList(),
    val errorDetail: String = "",
) {
    val dangerousMarkers: List<MountZygoteNextMarker>
        get() = isolatedMarkers.filter(MountZygoteNextMarker::dangerous)

    val leakDetected: Boolean
        get() = state == MountZygoteNextState.READY && dangerousMarkers.isNotEmpty()

    /**
     * AOSP init makes the root mount shared before creating its bootstrap/default namespaces.
     * Classic zygote clones that view and recursively changes its root to slave, while zygote_next
     * and its native descendants only fork and retain init's default namespace. The kernel assigns
     * fresh mount IDs while cloning a namespace. IDs can be reused, so ordering is corroborating
     * evidence only and is never accepted without the independent propagation contrast.
     */
    val namespaceAssessment: MountZygoteNextNamespaceAssessment
        get() {
            if (state != MountZygoteNextState.READY) {
                return MountZygoteNextNamespaceAssessment.UNVERIFIED
            }
            return if (
                namespaceSeparated &&
                propagationMatchesAosp &&
                mountIdOrderingMatchesAosp
            ) {
                MountZygoteNextNamespaceAssessment.INIT_MANAGED
            } else {
                MountZygoteNextNamespaceAssessment.UNVERIFIED
            }
        }

    val hasInitNamespaceCoverage: Boolean
        get() = namespaceAssessment == MountZygoteNextNamespaceAssessment.INIT_MANAGED

    val namespaceAssessmentDetail: String
        get() {
            if (hasInitNamespaceCoverage) {
                return "The native view matches AOSP's init-managed default namespace: " +
                    "it is distinct from the classic app namespace, its root is shared and " +
                    "non-slave, the classic root is slave, and its root/minimum mount IDs are older."
            }
            val reasons = buildList {
                if (!namespaceSeparated) add("namespace identities are missing or equal")
                if (!isolatedRootIsSharedNonSlave) {
                    add("native root is not shared and non-slave")
                }
                if (!mainRootIsSlaveNonShared) {
                    add("classic app root is not slave and non-shared")
                }
                if (!mountIdOrderingMatchesAosp) {
                    add("native root/minimum mount IDs are not older than the classic app IDs")
                }
            }
            return "Init-managed namespace coverage is unverified" +
                if (reasons.isEmpty()) "." else ": ${reasons.joinToString()}."
        }

    val contrastObserved: Boolean
        get() = hasInitNamespaceCoverage

    private val namespaceSeparated: Boolean
        get() = mainNamespaceInode > 0L && isolatedNamespaceInode > 0L &&
            mainNamespaceInode != isolatedNamespaceInode

    private val propagationMatchesAosp: Boolean
        get() = isolatedRootIsSharedNonSlave && mainRootIsSlaveNonShared

    private val isolatedRootIsSharedNonSlave: Boolean
        get() {
            val fields = propagationFields(isolatedPropagation)
            return fields.any { it.startsWith("shared:") } &&
                fields.none { it.startsWith("master:") }
        }

    private val mainRootIsSlaveNonShared: Boolean
        get() {
            val fields = propagationFields(mainPropagation)
            return fields.any { it.startsWith("master:") } &&
                fields.none { it.startsWith("shared:") }
        }

    private val mountIdOrderingMatchesAosp: Boolean
        get() = isolatedRootMountId > 0L && mainRootMountId > isolatedRootMountId &&
            isolatedMinimumMountId > 0L && mainMinimumMountId > isolatedMinimumMountId

    private fun propagationFields(value: String): List<String> {
        return value.split(' ').filter(String::isNotBlank)
    }

    companion object {
        fun pending(): MountZygoteNextReport {
            return MountZygoteNextReport(
                state = MountZygoteNextState.PENDING,
                sdkInt = 0,
            )
        }
    }
}

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
    val zygoteNext: MountZygoteNextReport = MountZygoteNextReport.pending(),
    val procMountViewProbeAvailable: Boolean = false,
    val procMountViewDistinctCount: Int = 0,
    val procMountViewExpectedCount: Int = 1,
    val procMountViewPidCount: Int = 0,
    val procMountViewDivergent: Boolean = false,
    val procMountViewTokenHit: Boolean = false,
    val procMountViewTokenKind: String = "",
    val procMountViewTokenDetail: String = "",
    val procMountViewDetail: String = "",
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

    val dangerSignalCount: Int
        get() = dangerFindings.size +
                (if (procMountViewTokenHit) 1 else 0) +
                (if (zygoteNext.leakDetected) 1 else 0)

    val warningSignalCount: Int
        get() = warningFindings.size + if (procMountViewDivergent && !procMountViewTokenHit) 1 else 0

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
