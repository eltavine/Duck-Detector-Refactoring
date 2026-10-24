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
import com.eltavine.duckdetector.features.mount.domain.MountFinding
import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity
import com.eltavine.duckdetector.features.mount.domain.MountMethodOutcome
import com.eltavine.duckdetector.features.mount.domain.MountMethodResult
import com.eltavine.duckdetector.features.mount.domain.MountReport
import com.eltavine.duckdetector.features.mount.domain.MountStage
import com.eltavine.duckdetector.features.mount.presentation.model.MountDetailRowModel

internal fun buildRows(
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

private fun findingRow(finding: MountFinding): MountDetailRowModel {
    return MountDetailRowModel(
        label = finding.label,
        value = badgeValue(finding.value),
        status = severityStatus(finding.severity),
        detail = finding.detail,
        detailMonospace = finding.detailMonospace,
    )
}

private fun badgeValue(value: String): String {
    return if (value.length > 18) value.take(17) + "…" else value
}

internal fun placeholderRows(
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

internal fun severityStatus(severity: MountFindingSeverity): DetectorStatus {
    return when (severity) {
        MountFindingSeverity.SAFE -> DetectorStatus.allClear()
        MountFindingSeverity.WARNING -> DetectorStatus.warning()
        MountFindingSeverity.DANGER -> DetectorStatus.danger()
        MountFindingSeverity.INFO -> DetectorStatus.info(InfoKind.SUPPORT)
    }
}

internal fun buildMethodRows(report: MountReport): List<MountDetailRowModel> {
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

private fun methodLabels(): List<String> = listOf(
    "Startup preload",
    "Zygote next mount view",
    "Anonymous device minors",
    "Path probes",
    "Shell tmp view",
    "/proc/self/mounts",
    "/proc/self/maps",
    "/proc/self/mountinfo",
    "Filesystem probes",
    "statx cross-check",
)

private fun methodStatus(result: MountMethodResult): DetectorStatus {
    return when (result.outcome) {
        MountMethodOutcome.CLEAN -> DetectorStatus.allClear()
        MountMethodOutcome.WARNING -> DetectorStatus.warning()
        MountMethodOutcome.DANGER -> DetectorStatus.danger()
        MountMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
    }
}
