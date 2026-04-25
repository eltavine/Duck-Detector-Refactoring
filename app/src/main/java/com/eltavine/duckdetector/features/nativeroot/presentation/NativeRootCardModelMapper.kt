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

package com.eltavine.duckdetector.features.nativeroot.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodOutcome
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodResult
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootStage
import com.eltavine.duckdetector.features.nativeroot.ui.model.NativeRootCardModel
import com.eltavine.duckdetector.features.nativeroot.ui.model.NativeRootDetailRowModel
import com.eltavine.duckdetector.features.nativeroot.ui.model.NativeRootHeaderFactModel
import com.eltavine.duckdetector.features.nativeroot.ui.model.NativeRootImpactItemModel

class NativeRootCardModelMapper {

    fun map(
        report: NativeRootReport,
    ): NativeRootCardModel {
        return NativeRootCardModel(
            title = "Native Root",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            nativeRows = buildNativeRows(report),
            runtimeRows = buildRuntimeRows(report),
            kernelRows = buildKernelRows(report),
            propertyRows = buildPropertyRows(report),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }

    private fun buildSubtitle(report: NativeRootReport): String {
        return when (report.stage) {
            NativeRootStage.LOADING -> "supercall + prctl + setresuid + runtime paths + /proc + isolated mount"
            NativeRootStage.FAILED -> "native root scan failed"
            NativeRootStage.READY -> when {
                !report.nativeAvailable && report.findings.isEmpty() -> "native detector unavailable"
                else -> "${report.pathCheckCount} paths · ${report.processCheckedCount} proc entries · ${report.cgroupPathCheckCount} cgroup dirs · ${report.kernelSourceCount} kernel sources · ${report.propertyCheckCount} props"
            }
        }
    }

    private fun buildVerdict(report: NativeRootReport): String {
        return when (report.stage) {
            NativeRootStage.LOADING -> "Scanning kernel-root indicators"
            NativeRootStage.FAILED -> "Native Root scan failed"
            NativeRootStage.READY -> when {
                report.kernelSuDetected && report.aPatchDetected -> "KernelSU and APatch indicators detected"
                report.selfSuDomain -> "Current app already runs in KernelSU su domain"
                report.kernelSuDetected && report.ksuSupercallProbeHit -> "KernelSU detected via ksu_driver"
                report.kernelSuDetected && report.prctlProbeHit -> "KernelSU detected via prctl"
                report.kernelSuDetected -> "KernelSU indicators detected"
                report.aPatchDetected -> "APatch indicators detected"
                report.magiskDetected -> "Magisk native indicators detected"
                report.hasDangerFindings -> "${report.dangerFindingCount} runtime root signal(s)"
                report.mountAnchorDriftCount > 0 -> "Isolated mount drift suggests namespace tampering"
                report.mountDriftSignalCount > 0 -> "Isolated-process namespace drift needs review"
                report.ksuManagerPackagePresent && report.ksuManagerTraitHitCount > 0 ->
                    "KernelSU manager weak fingerprint detected"

                report.ksuManagerPackagePresent -> "KernelSU manager package detected"
                report.hasWarningFindings -> "${report.warningFindingCount} native signal(s) need review"
                !report.nativeAvailable -> "Native detector unavailable"
                else -> "No native root indicators"
            }
        }
    }

    private fun buildSummary(report: NativeRootReport): String {
        val base = when (report.stage) {
            NativeRootStage.LOADING ->
                "Native probes are collecting read-only supercall, syscall, side-channel, self-process, isolated-process mount drift, manager manifest, path, cgroup, kernel-string, and property evidence."

            NativeRootStage.FAILED ->
                report.errorMessage ?: "Native Root scan failed before evidence could be assembled."

            NativeRootStage.READY -> when {
                report.hasDangerFindings ->
                    "Read-only ksu_driver hits, direct syscall hits, self-process IOC, root-manager paths, curated runtime residue paths, /data/local/tmp metadata drift, cgroup/process leakage, unexpected root processes, or isolated-process namespace drift indicate active native root infrastructure."

                report.hasWarningFindings ->
                    "Only weaker isolated-process mount drift, manager manifest fingerprints, process, cgroup, kernel, property, or metadata residue surfaced. These are review-worthy, but not as strong as direct native probes."

                !report.nativeAvailable ->
                    "This detector relies mostly on JNI-backed native probes. Native coverage was unavailable on this build, and the remaining runtime checks stayed clean."

                else ->
                    "KernelSU read-only supercall, prctl-side probes, self-process IOC, isolated-process mount drift, manager manifest fingerprint, SUSFS side-channel, /data/adb artifacts, curated tmp/system/storage residue paths, /data/local/tmp metadata, root-process audit, cgroup/process leakage, kernel strings, and properties stayed clean."
            }
        }
        if (report.stage != NativeRootStage.READY) {
            return base
        }
        return when {
            report.ksuSupercallBlocked ->
                "$base The read-only ksu_driver probe was blocked by app seccomp on this device, so the verdict falls back to prctl, self-process IOC, path, cgroup, kernel-string, and property evidence."

            !report.ksuSupercallAttempted ->
                "$base The read-only ksu_driver probe was unavailable, so this card relied on the remaining native checks."

            else -> base
        }
    }

    private fun buildHeaderFacts(report: NativeRootReport): List<NativeRootHeaderFactModel> {
        return when (report.stage) {
            NativeRootStage.LOADING -> placeholderFacts(
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            NativeRootStage.FAILED -> placeholderFacts("Error", DetectorStatus.info(InfoKind.ERROR))
            NativeRootStage.READY -> listOf(
                NativeRootHeaderFactModel(
                    label = "Flags",
                    value = familyValue(report),
                    status = when {
                        report.detectedFamilies.isEmpty() && report.nativeAvailable -> DetectorStatus.allClear()
                        report.detectedFamilies.isEmpty() -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.danger()
                    },
                ),
                NativeRootHeaderFactModel(
                    label = "Direct",
                    value = when {
                        report.directFindings.isNotEmpty() -> report.directFindings.size.toString()
                        report.ksuSupercallBlocked || !report.ksuSupercallAttempted -> "Limited"
                        else -> "Clean"
                    },
                    status = when {
                        report.directFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> DetectorStatus.danger()
                        report.directFindings.isNotEmpty() -> DetectorStatus.warning()
                        report.ksuSupercallBlocked || !report.ksuSupercallAttempted -> DetectorStatus.info(
                            InfoKind.SUPPORT
                        )
                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                NativeRootHeaderFactModel(
                    label = "Kernel",
                    value = if (report.kernelFindings.isEmpty()) "Clean" else report.kernelFindings.size.toString(),
                    status = when {
                        report.kernelFindings.isNotEmpty() -> DetectorStatus.warning()
                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                NativeRootHeaderFactModel(
                    label = "Runtime",
                    value = if (report.runtimeFindings.isEmpty()) {
                        if (report.nativeAvailable) "Clean" else "N/A"
                    } else {
                        report.runtimeFindings.size.toString()
                    },
                    status = when {
                        report.runtimeFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> DetectorStatus.danger()
                        report.runtimeFindings.isNotEmpty() -> DetectorStatus.warning()
                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
            )
        }
    }

    private fun buildNativeRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
        return when (report.stage) {
            NativeRootStage.LOADING -> placeholderRows(
                listOf("KSU supercall", "KernelSU prctl", "SUSFS side-channel"),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending",
            )

            NativeRootStage.FAILED -> placeholderRows(
                listOf("KSU supercall", "KernelSU prctl", "SUSFS side-channel"),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
            )

            NativeRootStage.READY -> buildList {
                addAll(report.directFindings.sortedBy { it.label }.map(::findingRow))
                if (report.ksuSupercallBlocked) {
                    add(
                        NativeRootDetailRowModel(
                            label = "KSU supercall",
                            value = "Blocked by seccomp",
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                            detail = "The sacrificial reboot() helper died under app seccomp before it could install a temporary [ksu_driver] fd. Other KernelSU checks still ran.",
                        )
                    )
                }
            }
        }
    }

    private fun buildRuntimeRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
        return when (report.stage) {
            NativeRootStage.LOADING -> placeholderRows(
                listOf(
                    "Self process IOC",
                    "Isolated mount drift",
                    "Manager fingerprint",
                    "Runtime paths",
                    "Root processes",
                    "Cgroup leakage",
                ),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending",
            )

            NativeRootStage.FAILED -> placeholderRows(
                listOf(
                    "Self process IOC",
                    "Isolated mount drift",
                    "Manager fingerprint",
                    "Runtime paths",
                    "Root processes",
                    "Cgroup leakage",
                ),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
            )

            NativeRootStage.READY -> report.runtimeFindings.sortedBy { it.label }.map(::findingRow)
        }
    }

    private fun buildKernelRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
        return when (report.stage) {
            NativeRootStage.LOADING -> placeholderRows(
                listOf("Kernel symbols", "Kernel modules", "Kernel identity"),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending",
            )

            NativeRootStage.FAILED -> placeholderRows(
                listOf("Kernel symbols", "Kernel modules", "Kernel identity"),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
            )

            NativeRootStage.READY -> report.kernelFindings.sortedBy { it.label }.map(::findingRow)
        }
    }

    private fun buildPropertyRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
        return when (report.stage) {
            NativeRootStage.LOADING -> placeholderRows(
                listOf("Root-specific properties"),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending",
                monospace = true,
            )

            NativeRootStage.FAILED -> placeholderRows(
                listOf("Root-specific properties"),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
                monospace = true,
            )

            NativeRootStage.READY -> report.propertyFindings.sortedBy { it.label }.map(::findingRow)
        }
    }

    private fun buildImpactItems(report: NativeRootReport): List<NativeRootImpactItemModel> {
        return when (report.stage) {
            NativeRootStage.LOADING -> listOf(
                NativeRootImpactItemModel(
                    text = "Gathering local native root evidence.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            NativeRootStage.FAILED -> listOf(
                NativeRootImpactItemModel(
                    text = report.errorMessage ?: "Native Root scan failed.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            NativeRootStage.READY -> buildList {
                if (report.hasDangerFindings) {
                    add(
                        NativeRootImpactItemModel(
                            text = "Direct native hits are stronger than plain package or property signals because they come from syscall behavior, runtime processes, cgroup visibility mismatches, or corroborated runtime residue paths.",
                            status = DetectorStatus.danger(),
                        ),
                    )
                } else if (report.hasWarningFindings) {
                    add(
                        NativeRootImpactItemModel(
                            text = "Isolated-process mount drift, manager manifest fingerprints, kernel strings, property residue, or cgroup leakage can indicate native-root history or selective runtime hiding, but they are weaker than direct syscall-side probes.",
                            status = DetectorStatus.warning(),
                        ),
                    )
                } else if (report.nativeAvailable) {
                    add(
                        NativeRootImpactItemModel(
                            text = "No common KernelSU, APatch, Magisk, SUSFS, or cgroup-leak traces surfaced from the current probe set.",
                            status = DetectorStatus.allClear(),
                        ),
                    )
                }
                add(
                    NativeRootImpactItemModel(
                        text = if (report.nativeAvailable) {
                            "A determined root can still hide or remove residue, so absence of native hits is not proof of a stock device."
                        } else {
                            "Native coverage was unavailable, so this card should not be treated as a strong clean verdict."
                        },
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )
            }
        }
    }

    private fun buildMethodRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
        return when (report.stage) {
            NativeRootStage.LOADING -> placeholderMethodRows(
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending"
            )

            NativeRootStage.FAILED -> placeholderMethodRows(
                DetectorStatus.info(InfoKind.ERROR),
                "Failed"
            )

            NativeRootStage.READY -> report.methods.map { result ->
                NativeRootDetailRowModel(
                    label = result.label,
                    value = result.summary,
                    status = methodStatus(result),
                    detail = result.detail,
                    detailMonospace = true,
                )
            }
        }
    }

    private fun buildScanRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
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
                    "Manager package",
                    "Manager traits",
                    "Cgroup paths",
                    "Cgroup visible",
                    "Cgroup proc",
                    "Cgroup denied",
                    "Cgroup hits",
                    "Kernel sources",
                    "Kernel hits",
                    "Properties checked",
                    "Property hits",
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
                    "Manager package",
                    "Manager traits",
                    "Cgroup paths",
                    "Cgroup visible",
                    "Cgroup proc",
                    "Cgroup denied",
                    "Cgroup hits",
                    "Kernel sources",
                    "Kernel hits",
                    "Properties checked",
                    "Property hits",
                    "Native library",
                ),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
            )

            NativeRootStage.READY -> listOf(
                NativeRootDetailRowModel(
                    "Paths checked",
                    report.pathCheckCount.toString(),
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
                        else -> "Clean"
                    },
                    when {
                        report.ksuManagerPackagePresent -> DetectorStatus.warning()
                        report.ksuManagerVisibilityRestricted -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.allClear()
                    },
                ),
                NativeRootDetailRowModel(
                    "Manager traits",
                    when {
                        report.ksuManagerPackagePresent -> "${report.ksuManagerTraitHitCount}/3"
                        report.ksuManagerVisibilityRestricted -> "N/A"
                        else -> "N/A"
                    },
                    when {
                        report.ksuManagerPackagePresent -> DetectorStatus.warning()
                        report.ksuManagerVisibilityRestricted -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.allClear()
                    },
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
                    "Native library",
                    if (report.nativeAvailable) "Loaded" else "Unavailable",
                    if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
            )
        }
    }

    private fun findingRow(finding: NativeRootFinding): NativeRootDetailRowModel {
        return NativeRootDetailRowModel(
            label = finding.label,
            value = finding.value,
            status = findingStatus(finding),
            detail = finding.detail,
            detailMonospace = finding.detailMonospace,
        )
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus,
    ): List<NativeRootHeaderFactModel> {
        return listOf(
            NativeRootHeaderFactModel("Flags", value, status),
            NativeRootHeaderFactModel("Direct", value, status),
            NativeRootHeaderFactModel("Kernel", value, status),
            NativeRootHeaderFactModel("Runtime", value, status),
        )
    }

    private fun placeholderRows(
        labels: List<String>,
        status: DetectorStatus,
        value: String,
        monospace: Boolean = false,
    ): List<NativeRootDetailRowModel> {
        return labels.map { label ->
            NativeRootDetailRowModel(
                label = label,
                value = value,
                status = status,
                detailMonospace = monospace,
            )
        }
    }

    private fun placeholderMethodRows(
        status: DetectorStatus,
        value: String,
    ): List<NativeRootDetailRowModel> {
        return listOf(
            "ksuReadonlySupercall",
            "prctlProbe",
            "susfsSideChannel",
            "selfProcessIoc",
            "isolatedMountDrift",
            "ksuManagerFingerprint",
            "runtimeArtifacts",
            "cgroupLeakage",
            "kernelTraces",
            "propertyResidue",
            "nativeLibrary",
            "signalSummary",
        ).map { label ->
            NativeRootDetailRowModel(
                label = label,
                value = value,
                status = status,
            )
        }
    }

    private fun familyValue(report: NativeRootReport): String {
        return when {
            report.detectedFamilies.isEmpty() && report.nativeAvailable -> "None"
            report.detectedFamilies.isEmpty() -> "N/A"
            report.detectedFamilies.size <= 2 -> report.detectedFamilies.joinToString("/")
            else -> report.detectedFamilies.take(2)
                .joinToString("/") + " +${report.detectedFamilies.size - 2}"
        }
    }

    private fun findingStatus(finding: NativeRootFinding): DetectorStatus {
        return when (finding.severity) {
            NativeRootFindingSeverity.DANGER -> DetectorStatus.danger()
            NativeRootFindingSeverity.WARNING -> DetectorStatus.warning()
            NativeRootFindingSeverity.INFO -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun methodStatus(result: NativeRootMethodResult): DetectorStatus {
        return when (result.outcome) {
            NativeRootMethodOutcome.CLEAN -> DetectorStatus.allClear()
            NativeRootMethodOutcome.DETECTED -> DetectorStatus.danger()
            NativeRootMethodOutcome.WARNING -> DetectorStatus.warning()
            NativeRootMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun NativeRootReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            NativeRootStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            NativeRootStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            NativeRootStage.READY -> when {
                hasDangerFindings -> DetectorStatus.danger()
                hasWarningFindings -> DetectorStatus.warning()
                !nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                else -> DetectorStatus.allClear()
            }
        }
    }
}
