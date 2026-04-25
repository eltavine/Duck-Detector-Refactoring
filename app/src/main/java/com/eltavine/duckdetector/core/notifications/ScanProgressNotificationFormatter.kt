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

package com.eltavine.duckdetector.core.notifications

import com.eltavine.duckdetector.core.ui.model.DetectionSeverity
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardOverviewModel
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

    fun format(snapshot: ScanProgressNotificationSnapshot): ScanProgressNotificationModel {
        val clampedTotal = snapshot.totalDetectorCount.coerceAtLeast(1)
        val clampedReady = snapshot.readyDetectorCount.coerceIn(0, clampedTotal)
        val progressPercent = ((clampedReady * 100f) / clampedTotal)
            .roundToInt()
            .coerceIn(0, 100)
        val overview = snapshot.dashboardOverview
        return if (snapshot.scanning) {
            ScanProgressNotificationModel(
                title = "Scanning $clampedReady/$clampedTotal",
                text = "${overview.headline} \u00b7 ${overview.summary}",
                subText = "Duck Detector",
                shortCriticalText = "$clampedReady/$clampedTotal",
                progressPercent = progressPercent,
            )
        } else {
            ScanProgressNotificationModel(
                title = overview.headline,
                text = overview.summary,
                subText = overview.title.takeIf { it.isNotBlank() && it != "Security overview" },
                shortCriticalText = shortCriticalTextFor(overview.headline),
                progressPercent = progressPercent,
            )
        }
    }

    private fun shortCriticalTextFor(
        headline: String,
    ): String? {
        return when (headline) {
            "Danger",
            "Warning",
            "Info",
            "OK" -> headline

            else -> null
        }
    }
}
