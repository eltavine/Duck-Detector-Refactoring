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

package com.eltavine.duckdetector.features.dashboard.ui

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardFindingKind
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardFindingModel
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardOverviewMetric
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardOverviewModel
import com.eltavine.duckdetector.features.dashboard.presentation.model.OverviewVerdict
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

@Composable
internal fun dashboardOverviewHeadline(model: DashboardOverviewModel): String = stringResource(
    when (model.verdict) {
        OverviewVerdict.DANGER -> R.string.dashboard_headline_danger
        OverviewVerdict.WARNING -> R.string.dashboard_headline_warning
        OverviewVerdict.INFO -> R.string.dashboard_headline_info
        OverviewVerdict.READY -> R.string.dashboard_headline_ready
        OverviewVerdict.PENDING -> R.string.dashboard_headline_pending
        OverviewVerdict.OK -> R.string.dashboard_headline_ok
    },
)

@Composable
internal fun dashboardOverviewSummary(model: DashboardOverviewModel): String {
    val focus = when (model.focusTitles.size) {
        0 -> ""
        1 -> model.focusTitles.first()
        else -> stringResource(
            R.string.dashboard_focus_pair,
            model.focusTitles[0],
            model.focusTitles[1],
        )
    }
    return when (model.verdict) {
        OverviewVerdict.DANGER -> stringResource(R.string.dashboard_summary_danger, focus)
        OverviewVerdict.WARNING -> stringResource(R.string.dashboard_summary_warning, focus)
        OverviewVerdict.INFO -> stringResource(R.string.dashboard_summary_info, focus)
        OverviewVerdict.READY -> stringResource(R.string.dashboard_summary_ready)
        OverviewVerdict.PENDING -> stringResource(R.string.dashboard_summary_pending)
        OverviewVerdict.OK -> stringResource(R.string.dashboard_summary_ok)
    }
}

@Composable
internal fun dashboardOverviewTitle(model: DashboardOverviewModel): String {
    if (!model.titleDescribesCompletedScan) {
        return stringResource(R.string.dashboard_security_overview)
    }
    val completedAt = requireNotNull(model.scanCompletedAtEpochMillis)
    val duration = requireNotNull(model.scanDurationMillis)
    return stringResource(
        R.string.dashboard_scan_completed_title,
        formatDashboardScanTime(completedAt),
        formatDashboardDuration(duration),
    )
}

@Composable
internal fun dashboardMetricLabel(metric: DashboardOverviewMetric): String = stringResource(
    when (metric) {
        DashboardOverviewMetric.DANGER -> R.string.dashboard_metric_danger
        DashboardOverviewMetric.WARNING -> R.string.dashboard_metric_warning
        DashboardOverviewMetric.READY -> R.string.dashboard_metric_ready
        DashboardOverviewMetric.PENDING -> R.string.dashboard_metric_pending
    },
)

@Composable
internal fun dashboardFindingTitle(finding: DashboardFindingModel): String = when (finding.kind) {
    DashboardFindingKind.DETECTOR -> finding.detectorTitle
    DashboardFindingKind.SCAN_STATUS -> stringResource(R.string.dashboard_finding_scan_status_title)
    DashboardFindingKind.OVERVIEW -> stringResource(R.string.dashboard_finding_overview_title)
}

@Composable
internal fun dashboardFindingHeadline(finding: DashboardFindingModel): String = when (finding.kind) {
    DashboardFindingKind.DETECTOR -> finding.headline
    DashboardFindingKind.SCAN_STATUS -> stringResource(R.string.dashboard_finding_scan_status_headline)
    DashboardFindingKind.OVERVIEW -> stringResource(R.string.dashboard_finding_overview_headline)
}

@Composable
internal fun dashboardFindingDetail(finding: DashboardFindingModel): String = when (finding.kind) {
    DashboardFindingKind.DETECTOR -> finding.detail
    DashboardFindingKind.SCAN_STATUS -> stringResource(R.string.dashboard_finding_scan_status_detail)
    DashboardFindingKind.OVERVIEW -> stringResource(R.string.dashboard_finding_overview_detail)
}

private fun formatDashboardScanTime(epochMillis: Long): String {
    val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.US)
    return Instant.ofEpochMilli(epochMillis)
        .atZone(ZoneId.systemDefault())
        .format(formatter)
}

@Composable
private fun formatDashboardDuration(durationMillis: Long): String {
    val value = when {
        durationMillis < 1_000L -> durationMillis.toString()
        durationMillis < 10_000L -> String.format(Locale.US, "%.1f", durationMillis / 1_000f)
        else -> ((durationMillis + 500L) / 1_000L).toString()
    }
    return if (durationMillis < 1_000L) {
        stringResource(R.string.dashboard_duration_ms, value)
    } else {
        stringResource(R.string.dashboard_duration_seconds, value)
    }
}
