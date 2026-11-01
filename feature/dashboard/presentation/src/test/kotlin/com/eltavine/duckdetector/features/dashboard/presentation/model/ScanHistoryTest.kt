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

import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.core.scan.DetectorSummary
import com.eltavine.duckdetector.core.scan.ScanState
import com.eltavine.duckdetector.core.scan.ScanTimeline
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanHistoryTest {
    @Test fun onlyCompletedScansBecomeHistory() {
        val summary = DetectorSummary(
            id = DetectorId("test"),
            title = "Test",
            status = DetectorStatus.danger(),
            headline = "Detected",
            summary = "",
            ready = false,
        )
        val loading = ScanState(
            detectors = listOf(summary),
            timeline = ScanTimeline(session = 1, startedAtElapsedMillis = 0),
        )
        assertEquals(null, loading.completedHistoricalVerdict())
        assertEquals(
            HistoricalVerdict.DANGER,
            loading.copy(
                detectors = listOf(summary.copy(ready = true)),
                timeline = loading.timeline.copy(finishedAtElapsedMillis = 1, completedAtEpochMillis = 3),
            ).completedHistoricalVerdict(),
        )
    }

    @Test fun infoFailureNeverBecomesGreen() {
        val summary = DetectorSummary(
            id = DetectorId("test"),
            title = "Test",
            status = DetectorStatus.info(InfoKind.ERROR),
            headline = "Unavailable",
            summary = "",
            ready = true,
        )
        val state = ScanState(
            detectors = listOf(summary),
            timeline = ScanTimeline(session = 1, startedAtElapsedMillis = 0, finishedAtElapsedMillis = 1, completedAtEpochMillis = 2),
        )
        assertEquals(HistoricalVerdict.INCONCLUSIVE, state.completedHistoricalVerdict())
    }

    @Test fun noCompletedColoredResultsKeepsPlaceholder() {
        assertTrue(ScanHistoryCounts(inconclusive = 3).segments().isEmpty())
    }

    @Test fun rareHistoricalOutcomeRetainsVisibleShare() {
        val sections = ScanHistoryCounts(danger = 1, clear = 99).segments()
        assertEquals(listOf(HistoricalVerdict.DANGER, HistoricalVerdict.CLEAR), sections.map { it.verdict })
        assertTrue(sections.first().fraction >= 0.08f)
        assertEquals(1f, sections.sumOf { it.fraction.toDouble() }.toFloat(), 0.0001f)
    }

    @Test fun allPresentColorsKeepFloorEvenWhenRare() {
        val sections = ScanHistoryCounts(danger = 1, warning = 1, clear = 1_000_000).segments()
        assertEquals(3, sections.size)
        assertTrue(sections.all { it.fraction >= 0.08f })
        assertEquals(1f, sections.sumOf { it.fraction.toDouble() }.toFloat(), 0.0001f)
    }

    @Test fun aSingleColorOccupiesTheWholeContour() {
        assertEquals(1f, ScanHistoryCounts(clear = 120).segments().single().fraction, 0.0001f)
    }
}
