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

package com.eltavine.duckdetector.features.nativeroot.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootStage
import com.eltavine.duckdetector.features.nativeroot.presentation.model.NativeRootDetailRowModel

internal fun buildScanRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
    return when (report.stage) {
        NativeRootStage.LOADING -> placeholderRows(
            listOf(
                "Paths checked",
                "Path hits",
                "Proc checked",
                "Proc denied",
                "Proc hits",
                "Self context",
                "Self driver FDs",
                "Self wrapper FDs",
                "Main mnt ns",
                "Isolated mnt ns",
                "Mount drift hits",
                "Mount anchor drifts",
                "Proc mount views",
                "Proc view expected",
                "Proc view pids",
                "Manager package",
                "Manager traits",
                "Throne hunt",
                "Throne hunt counters",
                "Cgroup paths",
                "Cgroup visible",
                "Cgroup proc",
                "Cgroup denied",
                "Cgroup hits",
                "Kernel sources",
                "Kernel hits",
                "Properties checked",
                "Property hits",
                "Temp root checked",
                "Temp root hits",
                "Native library",
            ),
            DetectorStatus.info(InfoKind.SUPPORT),
            "Pending",
        )

        NativeRootStage.FAILED -> placeholderRows(
            listOf(
                "Paths checked",
                "Path hits",
                "Proc checked",
                "Proc denied",
                "Proc hits",
                "Self context",
                "Self driver FDs",
                "Self wrapper FDs",
                "Main mnt ns",
                "Isolated mnt ns",
                "Mount drift hits",
                "Mount anchor drifts",
                "Proc mount views",
                "Proc view expected",
                "Proc view pids",
                "Manager package",
                "Manager traits",
                "Throne hunt",
                "Throne hunt counters",
                "Cgroup paths",
                "Cgroup visible",
                "Cgroup proc",
                "Cgroup denied",
                "Cgroup hits",
                "Kernel sources",
                "Kernel hits",
                "Properties checked",
                "Property hits",
                "Temp root checked",
                "Temp root hits",
                "Native library",
            ),
            DetectorStatus.info(InfoKind.ERROR),
            "Error",
        )

        NativeRootStage.READY -> listOf(
            NativeRootDetailRowModel(
                "Paths checked",
                if (report.pathDeniedCount > 0) {
                    "${report.pathCheckCount} · ${report.pathDeniedCount} not observable"
                } else {
                    report.pathCheckCount.toString()
                },
                DetectorStatus.info(InfoKind.SUPPORT)
            ),
            NativeRootDetailRowModel(
                "Path hits",
                report.pathHitCount.toString(),
                when {
                    report.findings.any {
                        it.group == NativeRootGroup.PATH &&
                            it.severity == NativeRootFindingSeverity.DANGER
                    } -> DetectorStatus.danger()

                    report.findings.any {
                        it.group == NativeRootGroup.PATH &&
                            it.severity == NativeRootFindingSeverity.WARNING
                    } -> DetectorStatus.warning()

                    report.nativeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            NativeRootDetailRowModel(
                "Proc checked",
                if (report.nativeAvailable) report.processCheckedCount.toString() else "N/A",
                if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            NativeRootDetailRowModel(
                "Proc denied",
                if (report.nativeAvailable) report.processDeniedCount.toString() else "N/A",
                DetectorStatus.info(InfoKind.SUPPORT),
            ),
            NativeRootDetailRowModel(
                "Proc hits",
                if (report.nativeAvailable) report.processHitCount.toString() else "N/A",
                when {
                    report.processHitCount > 0 -> DetectorStatus.danger()
                    report.nativeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            NativeRootDetailRowModel(
                "Self context",
                when {
                    report.selfContext.isNotBlank() -> report.selfContext
                    report.nativeAvailable -> "Unavailable"
                    else -> "N/A"
                },
                when {
                    report.selfSuDomain -> DetectorStatus.danger()
                    report.selfContext.isNotBlank() -> DetectorStatus.allClear()
                    report.nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            NativeRootDetailRowModel(
                "Self driver FDs",
                if (report.nativeAvailable) report.selfKsuDriverFdCount.toString() else "N/A",
                when {
                    report.selfKsuDriverFdCount > 0 -> DetectorStatus.danger()
                    report.nativeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            NativeRootDetailRowModel(
                "Self wrapper FDs",
                if (report.nativeAvailable) report.selfKsuFdwrapperFdCount.toString() else "N/A",
                when {
                    report.selfKsuFdwrapperFdCount > 0 -> DetectorStatus.danger()
                    report.nativeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            NativeRootDetailRowModel(
                "Main mnt ns",
                report.mainMountNamespaceInode.ifBlank { "Unavailable" },
                when {
                    report.mountDriftSignalCount > 0 -> DetectorStatus.warning()
                    report.mainMountNamespaceInode.isNotBlank() -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            NativeRootDetailRowModel(
                "Isolated mnt ns",
                when {
                    report.isolatedMountNamespaceInode.isNotBlank() -> report.isolatedMountNamespaceInode
                    report.isolatedMountProbeAvailable -> "Unavailable"
                    else -> "N/A"
                },
                when {
                    report.mountDriftSignalCount > 0 -> DetectorStatus.warning()
                    report.isolatedMountProbeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            NativeRootDetailRowModel(
                "Mount drift hits",
                if (report.isolatedMountProbeAvailable) report.mountDriftSignalCount.toString() else "N/A",
                when {
                    report.mountDriftSignalCount > 0 -> DetectorStatus.warning()
                    report.isolatedMountProbeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            NativeRootDetailRowModel(
                "Mount anchor drifts",
                if (report.isolatedMountProbeAvailable) report.mountAnchorDriftCount.toString() else "N/A",
                when {
                    report.mountAnchorDriftCount > 0 -> DetectorStatus.warning()
                    report.isolatedMountProbeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            NativeRootDetailRowModel(
                "Manager package",
                when {
                    report.ksuManagerPackagePresent -> "Present"
                    report.ksuManagerVisibilityRestricted -> "Scoped"
                    report.ksuManagerVisibilityUnknown -> "Unavailable"
                    else -> "Clean"
                },
                when {
                    report.ksuManagerPackagePresent -> DetectorStatus.warning()
                    report.ksuManagerVisibilityRestricted || report.ksuManagerVisibilityUnknown ->
                        DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.allClear()
                },
            ),
            NativeRootDetailRowModel(
                "Manager traits",
                when {
                    report.ksuManagerPackagePresent -> "${report.ksuManagerTraitHitCount}/3"
                    report.ksuManagerVisibilityRestricted || report.ksuManagerVisibilityUnknown -> "N/A"
                    else -> "N/A"
                },
                when {
                    report.ksuManagerPackagePresent -> DetectorStatus.warning()
                    report.ksuManagerVisibilityRestricted || report.ksuManagerVisibilityUnknown ->
                        DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.allClear()
                },
            ),
            NativeRootDetailRowModel(
                label = "Throne hunt",
                value = when {
                    report.ksuThroneHuntWatchDenied -> "Watch denied"
                    !report.ksuThroneHuntAvailable || !report.ksuThroneHuntStimulusApplied ->
                        report.ksuThroneHuntFailureStage
                    report.ksuThroneHuntHitCount > 0 ->
                        "open=${report.ksuThroneHuntOpenCount} access=${report.ksuThroneHuntAccessCount}"
                    else -> "No directory events"
                },
                status = DetectorStatus.info(InfoKind.SUPPORT),
                detail = "Unattributed directory activity; diagnostic only. " +
                    "Zero events cannot exclude KernelSU. Collection ${report.ksuThroneHuntCollectionOutcome}; " +
                    "baseline=${report.ksuThroneHuntBaselineHitCount}",
                hiddenCopyText = buildThroneHuntDiagnostics(report),
            ),
            NativeRootDetailRowModel(
                label = "Throne hunt counters",
                value = "open=${report.ksuThroneHuntOpenCount} " +
                    "access=${report.ksuThroneHuntAccessCount} " +
                    "raw=${report.ksuThroneHuntRawEventCount} " +
                    "invalid=${report.ksuThroneHuntInvalidEventCount} " +
                    "baseline=${report.ksuThroneHuntBaselineHitCount}",
                status = DetectorStatus.info(InfoKind.SUPPORT),
                detail = "Watch fd=${report.ksuThroneHuntWatchDescriptor}; " +
                    "stage=${report.ksuThroneHuntFailureStage}",
                hiddenCopyText = buildThroneHuntDiagnostics(report),
            ),
            NativeRootDetailRowModel(
                "Cgroup paths",
                if (report.cgroupAvailable) report.cgroupPathCheckCount.toString() else "N/A",
                if (report.cgroupAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            NativeRootDetailRowModel(
                "Cgroup visible",
                if (report.cgroupAvailable) report.cgroupAccessiblePathCount.toString() else "N/A",
                if (report.cgroupAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            NativeRootDetailRowModel(
                "Cgroup proc",
                if (report.cgroupAvailable) report.cgroupProcessCheckedCount.toString() else "N/A",
                if (report.cgroupAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            NativeRootDetailRowModel(
                "Cgroup denied",
                if (report.cgroupAvailable) report.cgroupProcDeniedCount.toString() else "N/A",
                DetectorStatus.info(InfoKind.SUPPORT),
            ),
            NativeRootDetailRowModel(
                "Cgroup hits",
                if (report.cgroupAvailable) report.cgroupHitCount.toString() else "N/A",
                when {
                    report.cgroupFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> DetectorStatus.danger()
                    report.cgroupHitCount > 0 -> DetectorStatus.warning()
                    report.cgroupAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            NativeRootDetailRowModel(
                "Kernel sources",
                if (report.nativeAvailable) report.kernelSourceCount.toString() else "N/A",
                if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            NativeRootDetailRowModel(
                "Kernel hits",
                if (report.nativeAvailable) report.kernelHitCount.toString() else "N/A",
                when {
                    report.kernelHitCount > 0 -> DetectorStatus.warning()
                    report.nativeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            NativeRootDetailRowModel(
                "Properties checked",
                if (report.nativeAvailable) report.propertyCheckCount.toString() else "N/A",
                if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            NativeRootDetailRowModel(
                "Property hits",
                if (report.nativeAvailable) report.propertyHitCount.toString() else "N/A",
                when {
                    report.propertyHitCount > 0 -> DetectorStatus.warning()
                    report.nativeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            NativeRootDetailRowModel(
                "Temp root checked",
                report.tempRootArtifactCheckCount.toString(),
                DetectorStatus.info(InfoKind.SUPPORT),
            ),
            NativeRootDetailRowModel(
                "Temp root hits",
                report.tempRootArtifactHitCount.toString(),
                when {
                    report.tempRootDetected -> DetectorStatus.danger()
                    report.tempRootArtifactCheckCount > 0 -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            NativeRootDetailRowModel(
                "Native library",
                if (report.nativeAvailable) "Loaded" else "Unavailable",
                if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
        )
    }
}
