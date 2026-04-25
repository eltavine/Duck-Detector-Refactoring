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

package com.eltavine.duckdetector.features.nativeroot.domain

enum class NativeRootStage {
    LOADING,
    READY,
    FAILED,
}

enum class NativeRootGroup(
    val label: String,
) {
    SYSCALL("Native probes"),
    SIDE_CHANNEL("Native probes"),
    PATH("Runtime artifacts"),
    PROCESS("Runtime artifacts"),
    PACKAGE("Runtime artifacts"),
    KERNEL("Kernel traces"),
    PROPERTY("Property residue"),
}

enum class NativeRootFindingSeverity(
    val label: String,
) {
    DANGER("Danger"),
    WARNING("Review"),
    INFO("Info"),
}

enum class NativeRootMethodOutcome {
    CLEAN,
    DETECTED,
    WARNING,
    SUPPORT,
}

data class NativeRootFinding(
    val id: String,
    val label: String,
    val value: String,
    val detail: String,
    val group: NativeRootGroup,
    val severity: NativeRootFindingSeverity,
    val detailMonospace: Boolean = false,
)

data class NativeRootMethodResult(
    val label: String,
    val summary: String,
    val outcome: NativeRootMethodOutcome,
    val detail: String,
)

data class NativeRootReport(
    val stage: NativeRootStage,
    val findings: List<NativeRootFinding>,
    val kernelSuDetected: Boolean,
    val aPatchDetected: Boolean,
    val magiskDetected: Boolean,
    val susfsDetected: Boolean,
    val kernelSuVersion: Long,
    val nativeAvailable: Boolean,
    val prctlProbeHit: Boolean,
    val susfsProbeHit: Boolean,
    val pathHitCount: Int,
    val pathCheckCount: Int,
    val processHitCount: Int,
    val processCheckedCount: Int,
    val processDeniedCount: Int,
    val cgroupAvailable: Boolean,
    val cgroupPathCheckCount: Int,
    val cgroupAccessiblePathCount: Int,
    val cgroupProcessCheckedCount: Int,
    val cgroupProcDeniedCount: Int,
    val cgroupHitCount: Int,
    val kernelHitCount: Int,
    val kernelSourceCount: Int,
    val propertyHitCount: Int,
    val propertyCheckCount: Int,
    val methods: List<NativeRootMethodResult>,
    val errorMessage: String? = null,
    val ksuSupercallAttempted: Boolean = false,
    val ksuSupercallProbeHit: Boolean = false,
    val ksuSupercallBlocked: Boolean = false,
    val ksuSupercallSafeMode: Boolean = false,
    val ksuSupercallLkm: Boolean = false,
    val ksuSupercallLateLoad: Boolean = false,
    val ksuSupercallPrBuild: Boolean = false,
    val ksuSupercallManager: Boolean = false,
    val selfSuDomain: Boolean = false,
    val selfContext: String = "",
    val selfKsuDriverFdCount: Int = 0,
    val selfKsuFdwrapperFdCount: Int = 0,
    val isolatedMountProbeAvailable: Boolean = false,
    val mainMountNamespaceInode: String = "",
    val isolatedMountNamespaceInode: String = "",
    val mountDriftSignalCount: Int = 0,
    val mountAnchorDriftCount: Int = 0,
    val ksuManagerPackagePresent: Boolean = false,
    val ksuManagerTraitHitCount: Int = 0,
    val ksuManagerVisibilityRestricted: Boolean = false,
) {
    val directFindings: List<NativeRootFinding>
        get() = findings.filter { it.group == NativeRootGroup.SYSCALL || it.group == NativeRootGroup.SIDE_CHANNEL }

    val runtimeFindings: List<NativeRootFinding>
        get() = findings.filter {
            it.group == NativeRootGroup.PATH ||
                    it.group == NativeRootGroup.PROCESS ||
                    it.group == NativeRootGroup.PACKAGE
        }

    val cgroupFindings: List<NativeRootFinding>
        get() = findings.filter { it.id.startsWith("cgroup_") }

    val kernelFindings: List<NativeRootFinding>
        get() = findings.filter { it.group == NativeRootGroup.KERNEL }

    val propertyFindings: List<NativeRootFinding>
        get() = findings.filter { it.group == NativeRootGroup.PROPERTY }

    val dangerFindingCount: Int
        get() = findings.count { it.severity == NativeRootFindingSeverity.DANGER }

    val warningFindingCount: Int
        get() = findings.count { it.severity == NativeRootFindingSeverity.WARNING }

    val hasDangerFindings: Boolean
        get() = dangerFindingCount > 0

    val hasWarningFindings: Boolean
        get() = warningFindingCount > 0

    val detectedFamilies: List<String>
        get() = buildList {
            if (kernelSuDetected) add("KSU")
            if (aPatchDetected) add("AP")
            if (magiskDetected) add("Mg")
            if (susfsDetected && !contains("SUSFS")) add("SUSFS")
        }

    companion object {
        fun loading(): NativeRootReport {
            return NativeRootReport(
                stage = NativeRootStage.LOADING,
                findings = emptyList(),
                kernelSuDetected = false,
                aPatchDetected = false,
                magiskDetected = false,
                susfsDetected = false,
                kernelSuVersion = 0L,
                nativeAvailable = true,
                prctlProbeHit = false,
                susfsProbeHit = false,
                pathHitCount = 0,
                pathCheckCount = 0,
                processHitCount = 0,
                processCheckedCount = 0,
                processDeniedCount = 0,
                cgroupAvailable = false,
                cgroupPathCheckCount = 0,
                cgroupAccessiblePathCount = 0,
                cgroupProcessCheckedCount = 0,
                cgroupProcDeniedCount = 0,
                cgroupHitCount = 0,
                kernelHitCount = 0,
                kernelSourceCount = 0,
                propertyHitCount = 0,
                propertyCheckCount = 0,
                methods = emptyList(),
            )
        }

        fun failed(message: String): NativeRootReport {
            return loading().copy(
                stage = NativeRootStage.FAILED,
                nativeAvailable = false,
                errorMessage = message,
            )
        }
    }
}
