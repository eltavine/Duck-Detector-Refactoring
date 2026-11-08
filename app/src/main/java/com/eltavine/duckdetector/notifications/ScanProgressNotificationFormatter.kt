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

package com.eltavine.duckdetector.notifications

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardOverviewModel
import com.eltavine.duckdetector.features.dashboard.presentation.model.OverviewVerdict
import kotlin.math.roundToInt

data class ScanProgressNotificationSnapshot(
    val totalDetectorCount: Int,
    val readyDetectorCount: Int,
    val dashboardOverview: DashboardOverviewModel,
    val scanning: Boolean,
)

data class ScanProgressNotificationModel(
    val title: String,
    val text: String,
    val subText: String?,
    val shortCriticalText: String?,
    val progressPercent: Int,
)

class ScanProgressNotificationFormatter {

    fun format(
        snapshot: ScanProgressNotificationSnapshot,
        scanningTitle: (ready: Int, total: Int) -> String,
    ): ScanProgressNotificationModel {
        val clampedTotal = snapshot.totalDetectorCount.coerceAtLeast(1)
        val clampedReady = snapshot.readyDetectorCount.coerceIn(0, clampedTotal)
        val progressPercent = ((clampedReady * 100f) / clampedTotal)
            .roundToInt()
            .coerceIn(0, 100)
        val overview = snapshot.dashboardOverview
        return if (snapshot.scanning) {
            ScanProgressNotificationModel(
                title = scanningTitle(clampedReady, clampedTotal),
                text = "${overview.headline} \u00b7 ${overview.summary}",
                subText = "Duck Detector",
                shortCriticalText = "$clampedReady/$clampedTotal",
                progressPercent = progressPercent,
            )
        } else {
            ScanProgressNotificationModel(
                title = overview.headline,
                text = overview.summary,
                subText = overview.title.takeIf { overview.titleDescribesCompletedScan },
                shortCriticalText = shortCriticalTextFor(overview),
                progressPercent = progressPercent,
            )
        }
    }

    private fun shortCriticalTextFor(
        overview: DashboardOverviewModel,
    ): String? {
        return when (overview.verdict) {
            OverviewVerdict.DANGER,
            OverviewVerdict.WARNING,
            OverviewVerdict.INFO,
            OverviewVerdict.OK -> overview.headline

            OverviewVerdict.READY,
            OverviewVerdict.PENDING -> null
        }
    }
}
