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

package com.eltavine.duckdetector.features.dashboard.presentation.model

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.core.scan.DetectorSummary
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

/** The counts the overview shows, in the order it shows them. */
enum class DashboardOverviewMetric(val label: String) {
    DANGER("Danger"),
    WARNING("Warning"),
    READY("Ready"),
    PENDING("Pending"),
}

data class DashboardOverviewMetricModel(
    val metric: DashboardOverviewMetric,
    val value: String,
    val status: DetectorStatus,
) {
    val label: String get() = metric.label
}

/** The overall outcome that [DashboardOverviewModel.headline] describes in words. */
enum class OverviewVerdict {
    DANGER,
    WARNING,
    INFO,
    READY,
    PENDING,
    OK,
}

data class DashboardOverviewModel(
    val title: String,
    val headline: String,
    val summary: String,
    val status: DetectorStatus,
    val metrics: List<DashboardOverviewMetricModel>,
    val verdict: OverviewVerdict,
    val focusTitles: List<String> = emptyList(),
    val scanDurationMillis: Long? = null,
    val scanCompletedAtEpochMillis: Long? = null,
    /** True when [title] reports the completion time and duration of a finished scan. */
    val titleDescribesCompletedScan: Boolean,
    val showTitleIcon: Boolean = false,
)

data class DashboardFindingModel(
    val detectorId: DetectorId? = null,
    val detectorTitle: String,
    val headline: String,
    val detail: String,
    val status: DetectorStatus,
    val kind: DashboardFindingKind = DashboardFindingKind.DETECTOR,
)

enum class DashboardFindingKind {
    DETECTOR,
    SCAN_STATUS,
    OVERVIEW,
}

data class DashboardUiState(
    val overview: DashboardOverviewModel,
    val topFindings: List<DashboardFindingModel>,
    /** Detector cards in display order: most severe first, then by title. */
    val cardOrder: List<DetectorId>,
    val isLoading: Boolean,
)

fun buildDashboardOverview(
    contributions: List<DetectorSummary>,
    scanDurationMillis: Long? = null,
    scanCompletedAtEpochMillis: Long? = null,
): DashboardOverviewModel {
    val total = contributions.size
    val readyCount = contributions.count { it.ready }
    val pendingCount = total - readyCount
    val dangerCount = contributions.count { it.status.severity == DetectionSeverity.DANGER }
    val warningCount = contributions.count { it.status.severity == DetectionSeverity.WARNING }
    val infoErrorCount = contributions.count {
        it.status.severity == DetectionSeverity.INFO && it.status.infoKind == InfoKind.ERROR
    }

    val focus = prioritizedContributions(contributions).take(2)
    val focusTitles = focus.map { it.title }

    val verdict = when {
        dangerCount > 0 -> OverviewVerdict.DANGER
        warningCount > 0 -> OverviewVerdict.WARNING
        infoErrorCount > 0 -> OverviewVerdict.INFO
        readyCount == 0 -> OverviewVerdict.READY
        pendingCount > 0 -> OverviewVerdict.PENDING
        else -> OverviewVerdict.OK
    }

    val overviewStatus = when (verdict) {
        OverviewVerdict.DANGER -> DetectorStatus.danger()
        OverviewVerdict.WARNING -> DetectorStatus.warning()
        OverviewVerdict.INFO -> DetectorStatus.info(InfoKind.ERROR)
        OverviewVerdict.READY,
        OverviewVerdict.PENDING -> DetectorStatus.info(InfoKind.SUPPORT)

        OverviewVerdict.OK -> DetectorStatus.allClear()
    }

    val headline = when (verdict) {
        OverviewVerdict.DANGER -> "Danger"
        OverviewVerdict.WARNING -> "Warning"
        OverviewVerdict.INFO -> "Info"
        OverviewVerdict.READY -> "Ready"
        OverviewVerdict.PENDING -> "Pending"
        OverviewVerdict.OK -> "OK"
    }

    val summary = when (verdict) {
        OverviewVerdict.DANGER -> "Start with ${focusTitles.joinToString(separator = " and ")}."
        OverviewVerdict.WARNING -> "Review ${focusTitles.joinToString(separator = " and ")} next."
        OverviewVerdict.INFO -> "${focusTitles.joinToString(separator = " and ")} need more context before treating results as clean."
        OverviewVerdict.READY -> "Detector cards will populate as local checks complete."
        OverviewVerdict.PENDING -> "Additional modules are still collecting their local evidence."
        OverviewVerdict.OK -> "Use the detector cards below to inspect local evidence in detail."
    }

    val titleDescribesCompletedScan =
        scanDurationMillis != null && scanCompletedAtEpochMillis != null && pendingCount == 0

    return DashboardOverviewModel(
        title = if (titleDescribesCompletedScan) {
            "Scanned at ${formatDetectedTimeLocal(requireNotNull(scanCompletedAtEpochMillis))}\nTotal time ${formatScanDuration(requireNotNull(scanDurationMillis))}"
        } else {
            "Security overview"
        },
        headline = headline,
        summary = summary,
        status = overviewStatus,
        verdict = verdict,
        focusTitles = focusTitles,
        scanDurationMillis = scanDurationMillis,
        scanCompletedAtEpochMillis = scanCompletedAtEpochMillis,
        titleDescribesCompletedScan = titleDescribesCompletedScan,
        metrics = listOf(
            DashboardOverviewMetricModel(
                metric = DashboardOverviewMetric.DANGER,
                value = dangerCount.toString(),
                status = if (dangerCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
            ),
            DashboardOverviewMetricModel(
                metric = DashboardOverviewMetric.WARNING,
                value = warningCount.toString(),
                status = if (warningCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
            ),
            DashboardOverviewMetricModel(
                metric = DashboardOverviewMetric.READY,
                value = readyCount.toString(),
                status = if (readyCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            DashboardOverviewMetricModel(
                metric = DashboardOverviewMetric.PENDING,
                value = pendingCount.toString(),
                status = if (pendingCount > 0) DetectorStatus.info(InfoKind.SUPPORT) else DetectorStatus.allClear(),
            ),
        ),
        showTitleIcon = scanDurationMillis != null && pendingCount == 0,
    )
}

private fun formatDetectedTimeLocal(epochMillis: Long): String {
    val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.US)
    return Instant.ofEpochMilli(epochMillis)
        .atZone(ZoneId.systemDefault())
        .format(formatter)
}

private fun formatScanDuration(
    durationMillis: Long,
): String {
    return when {
        durationMillis < 1_000L -> "${durationMillis}ms"
        durationMillis < 10_000L -> String.format(Locale.US, "%.1fs", durationMillis / 1_000f)
        else -> "${(durationMillis + 500L) / 1_000L}s"
    }
}

fun buildDashboardFindings(
    contributions: List<DetectorSummary>,
): List<DashboardFindingModel> {
    val prioritized = prioritizedContributions(contributions)
    val attentionFindings = prioritized.filter { contribution ->
        when (contribution.status.severity) {
            DetectionSeverity.DANGER,
            DetectionSeverity.WARNING -> true

            DetectionSeverity.INFO -> contribution.status.infoKind == InfoKind.ERROR
            DetectionSeverity.ALL_CLEAR -> false
        }
    }
    if (attentionFindings.isNotEmpty()) {
        return attentionFindings.take(3).map { contribution ->
            DashboardFindingModel(
                detectorId = contribution.id,
                detectorTitle = contribution.title,
                headline = contribution.headline,
                detail = contribution.findingDetail ?: contribution.summary,
                status = contribution.status,
            )
        }
    }

    if (contributions.any { !it.ready }) {
        return listOf(
            DashboardFindingModel(
                detectorTitle = "Scan status",
                headline = "Waiting for detector evidence",
                detail = "Detector cards will expand as modules finish collecting local evidence.",
                status = DetectorStatus.info(InfoKind.SUPPORT),
                kind = DashboardFindingKind.SCAN_STATUS,
            ),
        )
    }

    return listOf(
        DashboardFindingModel(
            detectorTitle = "Overview",
            headline = "No urgent findings in ready modules",
            detail = "Open detector cards below to review detailed local evidence and secondary checks.",
            status = DetectorStatus.allClear(),
            kind = DashboardFindingKind.OVERVIEW,
        ),
    )
}

private fun prioritizedContributions(
    contributions: List<DetectorSummary>,
): List<DetectorSummary> {
    return contributions.sortedWith(
        compareBy<DetectorSummary> { contribution ->
            detectorPriority(contribution.status)
        }.thenBy { if (it.ready) 0 else 1 }
            .thenBy { it.title },
    )
}

fun dashboardCardOrder(
    summaries: List<DetectorSummary>,
): List<DetectorId> {
    return summaries.sortedWith(
        compareBy<DetectorSummary> { summary ->
            detectorPriority(summary.status)
        }.thenBy { summary -> summary.title },
    ).map { it.id }
}

private fun detectorPriority(
    status: DetectorStatus,
): Int {
    return when (status.severity) {
        DetectionSeverity.DANGER -> 0
        DetectionSeverity.WARNING -> 1
        DetectionSeverity.INFO -> if (status.infoKind == InfoKind.ERROR) 2 else 3
        DetectionSeverity.ALL_CLEAR -> 4
    }
}
