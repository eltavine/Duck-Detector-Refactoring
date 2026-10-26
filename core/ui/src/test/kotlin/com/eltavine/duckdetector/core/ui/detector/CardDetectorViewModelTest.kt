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

package com.eltavine.duckdetector.core.ui.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.core.evidence.ScanEpoch
import com.eltavine.duckdetector.core.report.DetectorHeadline
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.core.scan.DetectorSummary
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class CardDetectorViewModelTest {

    private val dispatcher = UnconfinedTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(dispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `shows the loading card until the first scan finishes`() = runTest(dispatcher) {
        val scanner = GatedScanner()
        val viewModel = CardDetectorViewModel(ProbeDetector, scanner, ScanEpoch.begin(10_000_001L), { 20_000_001L })

        assertEquals(CardDetectorState(ready = false, cardModel = Card(0)), viewModel.state.value)
        assertEquals(summary(verdict = "report 0", ready = false), viewModel.summary.value)

        scanner.finish(7)

        assertEquals(CardDetectorState(ready = true, cardModel = Card(7)), viewModel.state.value)
        assertEquals(summary(verdict = "report 7", ready = true), viewModel.summary.value)
    }

    @Test
    fun `a rescan shows the loading card again and then publishes the new report`() = runTest(dispatcher) {
        val scanner = GatedScanner()
        val viewModel = CardDetectorViewModel(ProbeDetector, scanner, ScanEpoch.begin(10_000_001L), { 20_000_001L })
        scanner.finish(1)

        viewModel.rescan()
        assertEquals(CardDetectorState(ready = false, cardModel = Card(0)), viewModel.state.value)

        scanner.finish(2)
        assertEquals(CardDetectorState(ready = true, cardModel = Card(2)), viewModel.state.value)
        assertEquals(2, scanner.scans)
    }

    @Test
    fun `initial dashboard cards use the shared epoch and a rescan does not reuse it`() = runTest(dispatcher) {
        val batch = ScanEpoch.begin(12_345_678L)
        val firstScanner = GatedScanner()
        val secondScanner = GatedScanner()
        val first = CardDetectorViewModel(ProbeDetector, firstScanner, batch, { 20_000_001L })
        val second = CardDetectorViewModel(ProbeDetector, secondScanner, batch)

        assertEquals(batch.id, firstScanner.epochs.single().id)
        assertEquals(batch.id, secondScanner.epochs.single().id)
        firstScanner.finish(1)
        secondScanner.finish(2)
        first.rescan()
        assertEquals(2, firstScanner.epochs.size)
        org.junit.Assert.assertNotEquals(batch.id, firstScanner.epochs.last().id)
        assertEquals(1, secondScanner.epochs.size)
        firstScanner.finish(3)
    }

    private fun summary(verdict: String, ready: Boolean) = DetectorSummary(
        id = DetectorId("probe"),
        title = "Probe",
        status = DetectorStatus.info(InfoKind.SUPPORT),
        headline = verdict,
        summary = "summary",
        ready = ready,
    )

    private data class Card(val report: Int) : DetectorHeadline {
        override val title = "Probe"
        override val status = DetectorStatus.info(InfoKind.SUPPORT)
        override val verdict = "report $report"
        override val summary = "summary"
    }

    private object ProbeDetector : Detector<Int, Card> {
        override val id = DetectorId("probe")

        override fun createScanner(context: Context): DetectorScanner<Int> = error("tests pass the scanner")

        override fun loadingReport(): Int = 0

        override fun describe(report: Int): Card = Card(report)

        override fun export(model: Card): DetectorReport = error("not exported here")
    }

    /** A scanner whose scans finish only when the test says so. */
    private class GatedScanner : DetectorScanner<Int> {
        private var pending = CompletableDeferred<Int>()
        var scans = 0
        val epochs = mutableListOf<ScanEpoch>()

        override suspend fun scan(): Int {
            scans++
            epochs += ScanEpoch.current { error("Scan epoch was not provided") }
            return pending.await().also { pending = CompletableDeferred() }
        }

        fun finish(report: Int) {
            pending.complete(report)
        }
    }
}
