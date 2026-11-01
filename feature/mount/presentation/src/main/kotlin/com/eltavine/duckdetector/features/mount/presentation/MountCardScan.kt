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

package com.eltavine.duckdetector.features.mount.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.mount.domain.MountFindingOrigin
import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity
import com.eltavine.duckdetector.features.mount.domain.MountReport
import com.eltavine.duckdetector.features.mount.domain.MountStage
import com.eltavine.duckdetector.features.mount.presentation.model.MountDetailRowModel

internal fun buildScanRows(report: MountReport): List<MountDetailRowModel> {
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

private fun yesNo(value: Boolean): String = if (value) "Yes" else "No"

private fun boolStatus(value: Boolean): DetectorStatus {
    return if (value) DetectorStatus.allClear() else DetectorStatus.info(InfoKind.SUPPORT)
}

internal fun coveragePercent(report: MountReport): Int {
    return if (report.permissionTotal <= 0) {
        100
    } else {
        ((report.permissionAccessible.toDouble() / report.permissionTotal.toDouble()) * 100.0).toInt()
    }
}

private fun preloadStateLabel(report: MountReport): String {
    return when {
        !report.earlyPreloadAvailable -> "Unavailable"
        hasDangerPreloadEvidence(report) || hasWarningPreloadEvidence(report) -> "Detected"
        report.earlyPreloadFindingCount > 0 -> "Observation"
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
        report.earlyPreloadFindingCount > 0 -> DetectorStatus.info(InfoKind.SUPPORT)
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
        finding.origin != MountFindingOrigin.RUNTIME && finding.severity == MountFindingSeverity.DANGER
    }
}

private fun hasWarningPreloadEvidence(report: MountReport): Boolean {
    return report.findings.any { finding ->
        finding.origin == MountFindingOrigin.STARTUP_PRELOAD && finding.severity == MountFindingSeverity.WARNING
    }
}
