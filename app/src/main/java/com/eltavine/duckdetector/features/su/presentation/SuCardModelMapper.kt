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

package com.eltavine.duckdetector.features.su.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.su.domain.SuMethodOutcome
import com.eltavine.duckdetector.features.su.domain.SuMethodResult
import com.eltavine.duckdetector.features.su.domain.SuReport
import com.eltavine.duckdetector.features.su.domain.SuStage
import com.eltavine.duckdetector.features.su.ui.model.SuCardModel
import com.eltavine.duckdetector.features.su.ui.model.SuDetailRowModel
import com.eltavine.duckdetector.features.su.ui.model.SuHeaderFactModel
import com.eltavine.duckdetector.features.su.ui.model.SuImpactItemModel

class SuCardModelMapper {

    fun map(
        report: SuReport,
    ): SuCardModel {
        return SuCardModel(
            title = "SU",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            artifactRows = buildArtifactRows(report),
            contextRows = buildContextRows(report),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }

    private fun buildSubtitle(report: SuReport): String {
        return when (report.stage) {
            SuStage.LOADING -> "su paths + PATH + adb daemons + native context"
            SuStage.FAILED -> "local root probe failed"
            SuStage.READY -> buildString {
                append("${report.checkedSuPathCount} su paths")
                append(" · ${report.checkedDaemonPathCount} adb daemon paths")
                append(
                    if (report.nativeAvailable) {
                        " · native /proc scan"
                    } else {
                        " · fallback self context"
                    },
                )
            }
        }
    }

    private fun buildVerdict(report: SuReport): String {
        return when (report.stage) {
            SuStage.LOADING -> "Scanning root artifacts"
            SuStage.FAILED -> "SU scan failed"
            SuStage.READY -> when {
                report.daemons.isNotEmpty() -> "${daemonNames(report)} daemon detected"
                report.selfContextAbnormal || report.suspiciousProcesses.isNotEmpty() -> "Abnormal root context detected"
                report.suBinaries.isNotEmpty() -> "SU binary detected"
                !report.nativeAvailable -> "No root indicators from available probes"
                else -> "No root indicators"
            }
        }
    }

    private fun buildSummary(report: SuReport): String {
        return when (report.stage) {
            SuStage.LOADING ->
                "File, PATH, adb-daemon, SELinux context, and /proc visibility probes are collecting local evidence."

            SuStage.FAILED ->
                report.errorMessage ?: "SU scan failed before root evidence could be assembled."

            SuStage.READY -> when {
                report.daemons.isNotEmpty() ->
                    "${daemonNames(report)} footprints were found under /data/adb, which is a direct root-management signal."

                report.selfContextAbnormal || report.suspiciousProcesses.isNotEmpty() ->
                    "SELinux context probes surfaced abnormal app labels or corroborating root-like process-context residue."

                report.suBinaries.isNotEmpty() ->
                    "Common su binaries were found in system or adb-managed locations."

                !report.nativeAvailable ->
                    "File and daemon probes were clean, but JNI-backed /proc process enumeration was unavailable."

                else ->
                    "Common su binaries, adb daemons, and native SELinux context probes stayed clean."
            }
        }
    }

    private fun buildHeaderFacts(report: SuReport): List<SuHeaderFactModel> {
        return when (report.stage) {
            SuStage.LOADING -> placeholderFacts(
                value = "Pending",
                status = DetectorStatus.info(InfoKind.SUPPORT),
            )

            SuStage.FAILED -> listOf(
                SuHeaderFactModel("Artifacts", "Error", DetectorStatus.info(InfoKind.ERROR)),
                SuHeaderFactModel("Daemons", "Error", DetectorStatus.info(InfoKind.ERROR)),
                SuHeaderFactModel("Context", "Error", DetectorStatus.info(InfoKind.ERROR)),
                SuHeaderFactModel("Processes", "N/A", DetectorStatus.info(InfoKind.SUPPORT)),
            )

            SuStage.READY -> listOf(
                SuHeaderFactModel(
                    label = "Artifacts",
                    value = if (report.suBinaries.isEmpty()) "None" else report.suBinaries.size.toString(),
                    status = if (report.suBinaries.isEmpty()) DetectorStatus.allClear() else DetectorStatus.danger(),
                ),
                SuHeaderFactModel(
                    label = "Daemons",
                    value = if (report.daemons.isEmpty()) "None" else daemonNames(report),
                    status = if (report.daemons.isEmpty()) DetectorStatus.allClear() else DetectorStatus.danger(),
                ),
                SuHeaderFactModel(
                    label = "Context",
                    value = when {
                        report.selfContextAbnormal -> "Abnormal"
                        report.selfContext.isNotBlank() -> "Normal"
                        else -> "Unknown"
                    },
                    status = when {
                        report.selfContextAbnormal -> DetectorStatus.danger()
                        report.selfContext.isNotBlank() -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                SuHeaderFactModel(
                    label = "Processes",
                    value = when {
                        !report.nativeAvailable -> "N/A"
                        report.suspiciousProcesses.isEmpty() -> "0"
                        else -> report.suspiciousProcesses.size.toString()
                    },
                    status = when {
                        !report.nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                        report.suspiciousProcesses.isEmpty() -> DetectorStatus.allClear()
                        else -> DetectorStatus.danger()
                    },
                ),
            )
        }
    }

    private fun buildArtifactRows(report: SuReport): List<SuDetailRowModel> {
        return when (report.stage) {
            SuStage.LOADING -> listOf(
                SuDetailRowModel(
                    label = "Root daemons",
                    value = "Pending",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                SuDetailRowModel(
                    label = "SU binaries",
                    value = "Pending",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            SuStage.FAILED -> listOf(
                SuDetailRowModel(
                    label = "Root daemons",
                    value = "Error",
                    status = DetectorStatus.info(InfoKind.ERROR),
                    detail = report.errorMessage,
                ),
                SuDetailRowModel(
                    label = "SU binaries",
                    value = "Error",
                    status = DetectorStatus.info(InfoKind.ERROR),
                    detail = report.errorMessage,
                ),
            )

            SuStage.READY -> listOf(
                SuDetailRowModel(
                    label = "Root daemons",
                    value = if (report.daemons.isEmpty()) "None" else daemonNames(report),
                    status = if (report.daemons.isEmpty()) DetectorStatus.allClear() else DetectorStatus.danger(),
                    detail = report.daemons
                        .joinToString(separator = "\n") { finding -> "${finding.name}: ${finding.path}" }
                        .ifBlank { null },
                    detailMonospace = true,
                ),
                SuDetailRowModel(
                    label = "SU binaries",
                    value = if (report.suBinaries.isEmpty()) "None" else report.suBinaries.size.toString(),
                    status = if (report.suBinaries.isEmpty()) DetectorStatus.allClear() else DetectorStatus.danger(),
                    detail = report.suBinaries.joinToString(separator = "\n").ifBlank { null },
                    detailMonospace = true,
                ),
            )
        }
    }

    private fun buildContextRows(report: SuReport): List<SuDetailRowModel> {
        return when (report.stage) {
            SuStage.LOADING -> listOf(
                SuDetailRowModel(
                    label = "Self context",
                    value = "Pending",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                SuDetailRowModel(
                    label = "Suspicious processes",
                    value = "Pending",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                SuDetailRowModel(
                    label = "Probe path",
                    value = "Loading",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            SuStage.FAILED -> listOf(
                SuDetailRowModel(
                    label = "Self context",
                    value = "Error",
                    status = DetectorStatus.info(InfoKind.ERROR),
                    detail = report.errorMessage,
                ),
                SuDetailRowModel(
                    label = "Suspicious processes",
                    value = "Error",
                    status = DetectorStatus.info(InfoKind.ERROR),
                    detail = report.errorMessage,
                ),
                SuDetailRowModel(
                    label = "Probe path",
                    value = "Unavailable",
                    status = DetectorStatus.info(InfoKind.ERROR),
                    detail = report.errorMessage,
                ),
            )

            SuStage.READY -> listOf(
                SuDetailRowModel(
                    label = "Self context",
                    value = when {
                        report.selfContextAbnormal -> "Abnormal"
                        report.selfContext.isNotBlank() -> "Normal"
                        else -> "Unknown"
                    },
                    status = when {
                        report.selfContextAbnormal -> DetectorStatus.danger()
                        report.selfContext.isNotBlank() -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                    detail = report.selfContext.ifBlank {
                        "No SELinux context could be read from the current app process."
                    },
                    detailMonospace = report.selfContext.isNotBlank(),
                ),
                SuDetailRowModel(
                    label = "Suspicious processes",
                    value = when {
                        !report.nativeAvailable -> "Unavailable"
                        report.suspiciousProcesses.isEmpty() -> "None"
                        else -> report.suspiciousProcesses.size.toString()
                    },
                    status = when {
                        !report.nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                        report.suspiciousProcesses.isEmpty() -> DetectorStatus.allClear()
                        else -> DetectorStatus.danger()
                    },
                    detail = report.suspiciousProcesses.joinToString(separator = "\n").ifBlank {
                        if (report.nativeAvailable) {
                            "No suspicious process contexts matched root-related tokens."
                        } else {
                            "Native /proc process enumeration was unavailable on this build."
                        }
                    },
                    detailMonospace = true,
                ),
                SuDetailRowModel(
                    label = "Probe path",
                    value = when {
                        report.nativeAvailable -> "JNI syscall scan"
                        report.selfContext.isNotBlank() -> "Fallback self read"
                        else -> "Unavailable"
                    },
                    status = when {
                        report.nativeAvailable -> DetectorStatus.allClear()
                        report.selfContext.isNotBlank() -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.info(InfoKind.ERROR)
                    },
                    detail = if (report.nativeAvailable) {
                        "Checked ${report.checkedProcessCount} process contexts; ${report.deniedProcessCount} /proc reads were denied. Denied reads are kept as supporting visibility evidence, not direct root-process proof."
                    } else {
                        "Native library was unavailable, so only /proc/self/attr/current fallback could run."
                    },
                ),
            )
        }
    }

    private fun buildImpactItems(report: SuReport): List<SuImpactItemModel> {
        return when (report.stage) {
            SuStage.LOADING -> listOf(
                SuImpactItemModel(
                    text = "Gathering local root evidence.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            SuStage.FAILED -> listOf(
                SuImpactItemModel(
                    text = report.errorMessage ?: "SU scan failed.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            SuStage.READY -> when {
                report.hasRootIndicators -> listOf(
                    SuImpactItemModel(
                        text = "Privilege-escalation tooling is present or visible from this app context.",
                        status = DetectorStatus.danger(),
                    ),
                    SuImpactItemModel(
                        text = "Root managers can hide files, alter system behavior, and weaken app trust signals.",
                        status = DetectorStatus.danger(),
                    ),
                    SuImpactItemModel(
                        text = "Banking, payment, DRM, and integrity-sensitive apps may refuse to run.",
                        status = DetectorStatus.danger(),
                    ),
                )

                report.nativeAvailable -> listOf(
                    SuImpactItemModel(
                        text = "No common SU binaries or adb root daemons surfaced.",
                        status = DetectorStatus.allClear(),
                    ),
                    SuImpactItemModel(
                        text = "Native SELinux context probes stayed within normal app boundaries.",
                        status = DetectorStatus.allClear(),
                    ),
                    SuImpactItemModel(
                        text = "This remains heuristic evidence, not proof of an unmodified device.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )

                else -> listOf(
                    SuImpactItemModel(
                        text = "File and adb-daemon probes were clean.",
                        status = DetectorStatus.allClear(),
                    ),
                    SuImpactItemModel(
                        text = "Native /proc process-context coverage was unavailable on this build.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                    SuImpactItemModel(
                        text = "Absence of common SU artifacts is not proof that root is impossible.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )
            }
        }
    }

    private fun buildMethodRows(report: SuReport): List<SuDetailRowModel> {
        return when (report.stage) {
            SuStage.LOADING -> placeholderMethodRows(
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending"
            )

            SuStage.FAILED -> placeholderMethodRows(DetectorStatus.info(InfoKind.ERROR), "Failed")
            SuStage.READY -> report.methods.map { result ->
                SuDetailRowModel(
                    label = result.label,
                    value = result.summary,
                    status = methodStatus(result),
                    detail = result.detail,
                    detailMonospace = true,
                )
            }
        }
    }

    private fun buildScanRows(report: SuReport): List<SuDetailRowModel> {
        return when (report.stage) {
            SuStage.LOADING -> listOf(
                SuDetailRowModel(
                    "SU paths checked",
                    "Pending",
                    DetectorStatus.info(InfoKind.SUPPORT)
                ),
                SuDetailRowModel(
                    "Daemon paths checked",
                    "Pending",
                    DetectorStatus.info(InfoKind.SUPPORT)
                ),
                SuDetailRowModel(
                    "Proc contexts checked",
                    "Pending",
                    DetectorStatus.info(InfoKind.SUPPORT)
                ),
                SuDetailRowModel(
                    "Proc reads denied",
                    "Pending",
                    DetectorStatus.info(InfoKind.SUPPORT)
                ),
            )

            SuStage.FAILED -> listOf(
                SuDetailRowModel("SU paths checked", "Error", DetectorStatus.info(InfoKind.ERROR)),
                SuDetailRowModel(
                    "Daemon paths checked",
                    "Error",
                    DetectorStatus.info(InfoKind.ERROR)
                ),
                SuDetailRowModel(
                    "Proc contexts checked",
                    "N/A",
                    DetectorStatus.info(InfoKind.SUPPORT)
                ),
                SuDetailRowModel("Proc reads denied", "N/A", DetectorStatus.info(InfoKind.SUPPORT)),
            )

            SuStage.READY -> listOf(
                SuDetailRowModel(
                    label = "SU paths checked",
                    value = report.checkedSuPathCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                SuDetailRowModel(
                    label = "Daemon paths checked",
                    value = report.checkedDaemonPathCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                SuDetailRowModel(
                    label = "Proc contexts checked",
                    value = if (report.nativeAvailable) report.checkedProcessCount.toString() else "N/A",
                    status = when {
                        !report.nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                        report.checkedProcessCount > 0 -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                SuDetailRowModel(
                    label = "Proc reads denied",
                    value = if (report.nativeAvailable) report.deniedProcessCount.toString() else "N/A",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )
        }
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus,
    ): List<SuHeaderFactModel> {
        return listOf(
            SuHeaderFactModel("Artifacts", value, status),
            SuHeaderFactModel("Daemons", value, status),
            SuHeaderFactModel("Context", value, status),
            SuHeaderFactModel("Processes", value, status),
        )
    }

    private fun placeholderMethodRows(
        status: DetectorStatus,
        value: String,
    ): List<SuDetailRowModel> {
        return listOf(
            SuDetailRowModel("daemonScan", value, status),
            SuDetailRowModel("fileScan", value, status),
            SuDetailRowModel("nativeSyscall", value, status),
            SuDetailRowModel("nativeLibrary", value, status),
        )
    }

    private fun daemonNames(report: SuReport): String {
        val names = report.daemons.map { it.name }.distinct()
        return when {
            names.isEmpty() -> "None"
            names.size <= 2 -> names.joinToString("/")
            else -> names.take(2).joinToString("/") + " +${names.size - 2}"
        }
    }

    private fun methodStatus(result: SuMethodResult): DetectorStatus {
        return when (result.outcome) {
            SuMethodOutcome.CLEAN -> DetectorStatus.allClear()
            SuMethodOutcome.DETECTED -> DetectorStatus.danger()
            SuMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun SuReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            SuStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            SuStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            SuStage.READY -> when {
                hasRootIndicators -> DetectorStatus.danger()
                !nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                else -> DetectorStatus.allClear()
            }
        }
    }
}
