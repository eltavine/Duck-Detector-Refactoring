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

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardOverviewMetric
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardOverviewMetricModel
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardOverviewModel
import com.eltavine.duckdetector.features.dashboard.presentation.model.OverviewVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ScanProgressNotificationFormatterTest {

    private val formatter = ScanProgressNotificationFormatter()

    @Test
    fun `scanning snapshot uses progress title and dashboard summary`() {
        val model = formatter.format(
            ScanProgressNotificationSnapshot(
                totalDetectorCount = 15,
                readyDetectorCount = 6,
                dashboardOverview = overview(
                    title = "Security overview",
                    headline = "Danger",
                    summary = "Start with Mount and TEE.",
                    verdict = OverviewVerdict.DANGER,
                    completedScan = false,
                ),
                scanning = true,
            ),
            scanningTitle = { ready, total -> "Scanning $ready/$total" },
        )

        assertEquals("Scanning 6/15", model.title)
        assertEquals("Danger · Start with Mount and TEE.", model.text)
        assertEquals("6/15", model.shortCriticalText)
        assertEquals(40, model.progressPercent)
    }

    @Test
    fun `finished snapshot reuses dashboard headline and summary`() {
        val model = formatter.format(
            ScanProgressNotificationSnapshot(
                totalDetectorCount = 15,
                readyDetectorCount = 15,
                dashboardOverview = overview(
                    title = "Scan time 4.2s",
                    headline = "OK",
                    summary = "Use the detector cards below to inspect local evidence in detail.",
                    verdict = OverviewVerdict.OK,
                    completedScan = true,
                ),
                scanning = false,
            ),
            scanningTitle = { ready, total -> "Scanning $ready/$total" },
        )

        assertEquals("OK", model.title)
        assertEquals(
            "Use the detector cards below to inspect local evidence in detail.",
            model.text,
        )
        assertEquals("Scan time 4.2s", model.subText)
        assertEquals("OK", model.shortCriticalText)
        assertEquals(100, model.progressPercent)
    }

    @Test
    fun `pending verdicts carry no short critical text`() {
        listOf(OverviewVerdict.READY to "Ready", OverviewVerdict.PENDING to "Pending").forEach { (verdict, headline) ->
            val model = formatter.format(
                ScanProgressNotificationSnapshot(
                    totalDetectorCount = 15,
                    readyDetectorCount = 15,
                    dashboardOverview = overview(
                        title = "Security overview",
                        headline = headline,
                        summary = "summary",
                        verdict = verdict,
                        completedScan = false,
                    ),
                    scanning = false,
                ),
                scanningTitle = { ready, total -> "Scanning $ready/$total" },
            )

            assertNull(model.shortCriticalText)
            assertNull(model.subText)
        }
    }

    @Test
    fun `sub text follows the completed scan flag rather than the title wording`() {
        val model = formatter.format(
            ScanProgressNotificationSnapshot(
                totalDetectorCount = 15,
                readyDetectorCount = 15,
                dashboardOverview = overview(
                    title = "Any reworded overview title",
                    headline = "Warning",
                    summary = "summary",
                    verdict = OverviewVerdict.WARNING,
                    completedScan = false,
                ),
                scanning = false,
            ),
            scanningTitle = { ready, total -> "Scanning $ready/$total" },
        )

        assertNull(model.subText)
        assertEquals("Warning", model.shortCriticalText)
    }

    private fun overview(
        title: String,
        headline: String,
        summary: String,
        verdict: OverviewVerdict,
        completedScan: Boolean,
    ) = DashboardOverviewModel(
        title = title,
        headline = headline,
        summary = summary,
        status = DetectorStatus.allClear(),
        verdict = verdict,
        titleDescribesCompletedScan = completedScan,
        metrics = listOf(
            DashboardOverviewMetricModel(
                metric = DashboardOverviewMetric.READY,
                value = "15",
                status = DetectorStatus.allClear(),
            ),
        ),
    )
}
