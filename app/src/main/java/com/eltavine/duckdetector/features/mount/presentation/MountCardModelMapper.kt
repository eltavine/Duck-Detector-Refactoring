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

package com.eltavine.duckdetector.features.mount.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.mount.domain.MountFinding
import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity
import com.eltavine.duckdetector.features.mount.domain.MountMethodOutcome
import com.eltavine.duckdetector.features.mount.domain.MountMethodResult
import com.eltavine.duckdetector.features.mount.domain.MountReport
import com.eltavine.duckdetector.features.mount.domain.MountStage
import com.eltavine.duckdetector.features.mount.ui.model.MountCardModel
import com.eltavine.duckdetector.features.mount.ui.model.MountDetailRowModel
import com.eltavine.duckdetector.features.mount.ui.model.MountHeaderFactModel
import com.eltavine.duckdetector.features.mount.ui.model.MountImpactItemModel

class MountCardModelMapper {

    fun map(
        report: MountReport,
    ): MountCardModel {
        return MountCardModel(
            title = "Mount",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            artifactRows = buildRows(
                report.stage,
                report.artifactRows,
                listOf("Magisk mounts", "Zygisk/Riru", "/data/adb", "Debug ramdisk")
            ),
            runtimeRows = buildRows(
                report.stage,
                report.runtimeRows,
                listOf("System RW", "Overlay mounts", "Loop devices", "dm-verity bypass")
            ),
            filesystemRows = buildRows(
                report.stage,
                report.filesystemRows,
                listOf("Overlayfs support", "System filesystem type", "Tmpfs anomaly")
            ),
            consistencyRows = buildRows(
                report.stage,
                report.consistencyRows,
                listOf(
                    "Namespace access",
                    "Shell tmp view",
                    "Mount consistency",
                    "Mount ID loophole",
                    "Bind mount root"
                )
            ),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }

    private fun buildSubtitle(report: MountReport): String {
        return when (report.stage) {
            MountStage.LOADING -> "mounts + mountinfo + maps + statfs + statx"
            MountStage.FAILED -> "local mount scan failed"
            MountStage.READY -> "${report.mountEntryCount} mounts · ${report.mountInfoEntryCount} mountinfo · ${report.mapLineCount} map lines"
        }
    }

    private fun buildVerdict(report: MountReport): String {
        return when (report.stage) {
            MountStage.LOADING -> "Scanning runtime mount visibility"
            MountStage.FAILED -> "Mount scan failed"
            MountStage.READY -> when {
                report.dangerFindings.isNotEmpty() && hasOnlyPreloadEvidence(report) ->
                    "${report.dangerFindings.size} critical startup signal(s)"

                report.dangerFindings.isNotEmpty() -> "${report.dangerFindings.size} critical mount signal(s)"
                report.warningFindings.isNotEmpty() && hasOnlyPreloadEvidence(report) ->
                    "${report.warningFindings.size} startup signal(s) need review"

                report.warningFindings.isNotEmpty() -> "${report.warningFindings.size} mount signal(s) need review"
                else -> "No suspicious mount-layer signal"
            }
        }
    }

    private fun buildSummary(report: MountReport): String {
        return when (report.stage) {
            MountStage.LOADING ->
                "Mount table, mountinfo, memory maps, filesystem type, and path-based root artifact probes are collecting local evidence."

            MountStage.FAILED ->
                report.errorMessage ?: "Mount scan failed before evidence could be assembled."

            MountStage.READY -> if (hasOnlyPreloadEvidence(report) && report.dangerFindings.isNotEmpty()) {
                "Startup preload captured early namespace or mount anomalies before the normal runtime scan settled."
            } else if (hasOnlyPreloadEvidence(report) && report.warningFindings.isNotEmpty()) {
                "Startup preload captured weaker early mount inconsistencies that still merit review."
            } else when {
                report.dangerFindings.isNotEmpty() ->
                    "The current app mount view contains root-managed overlays, writable-system behavior, selective shell-tmp concealment, hidden mount inconsistencies, or strong runtime artifacts."

                report.warningFindings.isNotEmpty() ->
                    "The mount layer is not obviously compromised, but it still contains review-worthy runtime or filesystem drift."

                else ->
                    "No suspicious Magisk, overlay, writable-system, or mount-coherence artifact surfaced from the current app context."
            }
        }
    }

    private fun buildHeaderFacts(report: MountReport): List<MountHeaderFactModel> {
        return when (report.stage) {
            MountStage.LOADING -> placeholderFacts("Pending", DetectorStatus.info(InfoKind.SUPPORT))
            MountStage.FAILED -> placeholderFacts("Error", DetectorStatus.info(InfoKind.ERROR))
            MountStage.READY -> listOf(
                MountHeaderFactModel(
                    label = "Critical",
                    value = countLabel(report.dangerFindings.size),
                    status = if (report.dangerFindings.isEmpty()) DetectorStatus.allClear() else DetectorStatus.danger(),
                ),
                MountHeaderFactModel(
                    label = "Review",
                    value = countLabel(report.warningFindings.size),
                    status = if (report.warningFindings.isEmpty()) DetectorStatus.allClear() else DetectorStatus.warning(),
                ),
                MountHeaderFactModel(
                    label = "Coverage",
                    value = "${coveragePercent(report)}%",
                    status = when {
                        report.permissionDenied == 0 -> DetectorStatus.allClear()
                        report.permissionDenied * 2 >= report.permissionTotal && report.permissionTotal > 0 -> DetectorStatus.warning()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                MountHeaderFactModel(
                    label = "Native",
                    value = if (report.nativeAvailable) "Loaded" else "N/A",
                    status = if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
            )
        }
    }

    private fun buildRows(
        stage: MountStage,
        rows: List<MountFinding>,
        placeholders: List<String>,
    ): List<MountDetailRowModel> {
        return when (stage) {
            MountStage.LOADING -> placeholderRows(
                placeholders,
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            MountStage.FAILED -> placeholderRows(
                placeholders,
                "Error",
                DetectorStatus.info(InfoKind.ERROR)
            )

            MountStage.READY -> if (rows.isEmpty()) {
                listOf(
                    MountDetailRowModel(
                        label = "Status",
                        value = "Clean",
                        status = DetectorStatus.allClear(),
                        detail = "No findings were produced for this section.",
                    ),
                )
            } else {
                rows.map(::findingRow)
            }
        }
    }

    private fun buildImpactItems(report: MountReport): List<MountImpactItemModel> {
        return when (report.stage) {
            MountStage.LOADING -> listOf(
                MountImpactItemModel(
                    text = "Gathering runtime mount and filesystem evidence.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            MountStage.FAILED -> listOf(
                MountImpactItemModel(
                    text = report.errorMessage ?: "Mount scan failed.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            MountStage.READY -> report.impacts.map {
                MountImpactItemModel(
                    text = it.text,
                    status = severityStatus(it.severity),
                )
            }
        }
    }

    private fun buildMethodRows(report: MountReport): List<MountDetailRowModel> {
        return when (report.stage) {
            MountStage.LOADING -> placeholderRows(
                methodLabels(),
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            MountStage.FAILED -> placeholderRows(
                methodLabels(),
                "Failed",
                DetectorStatus.info(InfoKind.ERROR)
            )

            MountStage.READY -> report.methods.map { result ->
                MountDetailRowModel(
                    label = result.label,
                    value = result.summary,
                    status = methodStatus(result),
                    detail = result.detail,
                    detailMonospace = true,
                )
            }
        }
    }

    private fun buildScanRows(report: MountReport): List<MountDetailRowModel> {
        return when (report.stage) {
            MountStage.LOADING -> placeholderRows(
                scanLabels(),
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            MountStage.FAILED -> placeholderRows(
                scanLabels(),
                "Error",
                DetectorStatus.info(InfoKind.ERROR)
            )

            MountStage.READY -> listOf(
                MountDetailRowModel(
                    "Startup preload",
                    preloadStateLabel(report),
                    preloadStatus(report),
                ),
                MountDetailRowModel(
                    "Preload context",
                    preloadContextLabel(report),
                    preloadContextStatus(report),
                ),
                MountDetailRowModel(
                    "Preload findings",
                    if (report.earlyPreloadAvailable) report.earlyPreloadFindingCount.toString() else "N/A",
                    preloadStatus(report),
                ),
                MountDetailRowModel(
                    "Mount entries",
                    report.mountEntryCount.toString(),
                    DetectorStatus.info(InfoKind.SUPPORT)
                ),
                MountDetailRowModel(
                    "Mountinfo entries",
                    report.mountInfoEntryCount.toString(),
                    DetectorStatus.info(InfoKind.SUPPORT)
                ),
                MountDetailRowModel(
                    "Map lines",
                    report.mapLineCount.toString(),
                    DetectorStatus.info(InfoKind.SUPPORT)
                ),
                MountDetailRowModel(
                    "Permission denied",
                    report.permissionDenied.toString(),
                    when {
                        report.permissionDenied == 0 -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                MountDetailRowModel(
                    "Coverage",
                    "${coveragePercent(report)}%",
                    when {
                        report.permissionDenied == 0 -> DetectorStatus.allClear()
                        report.permissionDenied * 2 >= report.permissionTotal && report.permissionTotal > 0 -> DetectorStatus.warning()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                MountDetailRowModel(
                    "Mounts readable",
                    yesNo(report.mountsReadable),
                    boolStatus(report.mountsReadable),
                ),
                MountDetailRowModel(
                    "Mountinfo readable",
                    yesNo(report.mountInfoReadable),
                    boolStatus(report.mountInfoReadable),
                ),
                MountDetailRowModel(
                    "Maps readable",
                    yesNo(report.mapsReadable),
                    boolStatus(report.mapsReadable),
                ),
                MountDetailRowModel(
                    "statx support",
                    yesNo(report.statxSupported),
                    if (report.statxSupported) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
            )
        }
    }

    private fun findingRow(finding: MountFinding): MountDetailRowModel {
        return MountDetailRowModel(
            label = finding.label,
            value = badgeValue(finding.value),
            status = severityStatus(finding.severity),
            detail = finding.detail,
            detailMonospace = finding.detailMonospace,
        )
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus
    ): List<MountHeaderFactModel> {
        return listOf(
            MountHeaderFactModel("Critical", value, status),
            MountHeaderFactModel("Review", value, status),
            MountHeaderFactModel("Coverage", value, status),
            MountHeaderFactModel("Native", value, status),
        )
    }

    private fun placeholderRows(
        labels: List<String>,
        value: String,
        status: DetectorStatus
    ): List<MountDetailRowModel> {
        return labels.map { label ->
            MountDetailRowModel(
                label = label,
                value = value,
                status = status,
            )
        }
    }

    private fun methodLabels(): List<String> = listOf(
        "Startup preload",
        "Path probes",
        "Shell tmp view",
        "/proc/self/mounts",
        "/proc/self/maps",
        "/proc/self/mountinfo",
        "Filesystem probes",
        "statx cross-check",
    )

    private fun scanLabels(): List<String> = listOf(
        "Startup preload",
        "Preload context",
        "Preload findings",
        "Mount entries",
        "Mountinfo entries",
        "Map lines",
        "Permission denied",
        "Coverage",
        "Mounts readable",
        "Mountinfo readable",
        "Maps readable",
        "statx support",
    )

    private fun severityStatus(severity: MountFindingSeverity): DetectorStatus {
        return when (severity) {
            MountFindingSeverity.SAFE -> DetectorStatus.allClear()
            MountFindingSeverity.WARNING -> DetectorStatus.warning()
            MountFindingSeverity.DANGER -> DetectorStatus.danger()
            MountFindingSeverity.INFO -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun methodStatus(result: MountMethodResult): DetectorStatus {
        return when (result.outcome) {
            MountMethodOutcome.CLEAN -> DetectorStatus.allClear()
            MountMethodOutcome.WARNING -> DetectorStatus.warning()
            MountMethodOutcome.DANGER -> DetectorStatus.danger()
            MountMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun countLabel(count: Int): String = if (count == 0) "None" else count.toString()

    private fun yesNo(value: Boolean): String = if (value) "Yes" else "No"

    private fun boolStatus(value: Boolean): DetectorStatus {
        return if (value) DetectorStatus.allClear() else DetectorStatus.info(InfoKind.SUPPORT)
    }

    private fun coveragePercent(report: MountReport): Int {
        return if (report.permissionTotal <= 0) {
            100
        } else {
            ((report.permissionAccessible.toDouble() / report.permissionTotal.toDouble()) * 100.0).toInt()
        }
    }

    private fun badgeValue(value: String): String {
        return if (value.length > 18) value.take(17) + "…" else value
    }

    private fun preloadStateLabel(report: MountReport): String {
        return when {
            !report.earlyPreloadAvailable -> "Unavailable"
            report.earlyPreloadDetected -> "Detected"
            else -> "Clean"
        }
    }

    private fun preloadContextLabel(report: MountReport): String {
        return when {
            !report.earlyPreloadAvailable -> "N/A"
            report.earlyPreloadContextValid -> "Fresh"
            else -> "Stale"
        }
    }

    private fun preloadStatus(report: MountReport): DetectorStatus {
        return when {
            !report.earlyPreloadAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
            hasDangerPreloadEvidence(report) -> DetectorStatus.danger()
            hasWarningPreloadEvidence(report) -> DetectorStatus.warning()
            else -> DetectorStatus.allClear()
        }
    }

    private fun preloadContextStatus(report: MountReport): DetectorStatus {
        return when {
            !report.earlyPreloadAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
            report.earlyPreloadContextValid -> DetectorStatus.allClear()
            else -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun hasDangerPreloadEvidence(report: MountReport): Boolean {
        return report.findings.any { finding ->
            (finding.id.startsWith("early_preload_") || finding.detail.orEmpty()
                .contains("Startup preload:")) &&
                    finding.severity == MountFindingSeverity.DANGER
        }
    }

    private fun hasWarningPreloadEvidence(report: MountReport): Boolean {
        return report.findings.any { finding ->
            finding.id.startsWith("early_preload_") && finding.severity == MountFindingSeverity.WARNING
        }
    }

    private fun hasOnlyPreloadEvidence(report: MountReport): Boolean {
        val findings = report.findings.filter {
            it.severity == MountFindingSeverity.DANGER || it.severity == MountFindingSeverity.WARNING
        }
        return findings.isNotEmpty() && findings.all { it.id.startsWith("early_preload_") }
    }

    private fun MountReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            MountStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            MountStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            MountStage.READY -> when {
                dangerFindings.isNotEmpty() -> DetectorStatus.danger()
                warningFindings.isNotEmpty() -> DetectorStatus.warning()
                else -> DetectorStatus.allClear()
            }
        }
    }
}
