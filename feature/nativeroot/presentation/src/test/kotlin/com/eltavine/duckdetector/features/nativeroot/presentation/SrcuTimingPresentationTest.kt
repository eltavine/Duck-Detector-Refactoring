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

package com.eltavine.duckdetector.features.nativeroot.presentation

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.report.ReportBlock
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootStage
import com.eltavine.duckdetector.features.nativeroot.domain.ROUND_COUNT
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuCloseSample
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuCloseStage
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingObservation
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingRound
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingVerdict
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingWindow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SrcuTimingPresentationTest {
    @Test fun `disabled unsupported and failed experiments stay support rows`() {
        for (state in SrcuTimingCollection.entries.filter { it != SrcuTimingCollection.COLLECTED }) {
            val row = srcuTimingRow(SrcuTimingObservation(collection = state))
            assertEquals(DetectionSeverity.INFO, row.status.severity)
            assertEquals("fsnotifySrcuCloseTiming", row.label)
            assertNotNull(row.hiddenCopyText)
        }
    }
    @Test fun `mapper carries experiment failures into the SDK export`() {
        val report = NativeRootReport.loading().copy(stage = NativeRootStage.READY,
            srcuTiming = SrcuTimingObservation(SrcuTimingCollection.TIMED_OUT,
                failureDetail = "cleanup unconfirmed"))
        val model = NativeRootCardModelMapper().map(report)
        val row = model.methodRows.single { it.label == "fsnotifySrcuCloseTiming" }
        assertEquals(DetectionSeverity.INFO, model.status.severity)
        val exported = model.toDetectorReport().blocks.filterIsInstance<ReportBlock.Rows>()
            .flatMap { it.rows }.single { it.label == row.label }
        assertEquals(row.detail, exported.detail)
        assertTrue(exported.detail.orEmpty().contains("cleanup unconfirmed"))
    }
    @Test fun `failed errno appears in exportable diagnostics`() {
        val row = srcuTimingRow(SrcuTimingObservation(collection = SrcuTimingCollection.NATIVE_FAILED,
            failedWindow = SrcuTimingWindow(0, 0, false,
                listOf(SrcuCloseSample(0, 0, SrcuCloseStage.INIT_FAILED, 24)))))
        assertTrue(row.detail.orEmpty().contains("errno=24"))
    }

    private fun closes(delay: Long) = SrcuTimingWindow(1000, 100000, false,
        List(16) { SrcuCloseSample(1000L + it * 1000, 1000L + it * 1000 + delay, SrcuCloseStage.OK) })
    private val delayed = SrcuTimingObservation(SrcuTimingCollection.COLLECTED,
        List(ROUND_COUNT) { SrcuTimingRound(closes(100), closes(5000), closes(100)) }, cleanupCompleted = true)
    private val delayedReport = NativeRootReport.loading().copy(stage = NativeRootStage.READY, srcuTiming = delayed)

    @Test fun `the experiment names the card only when no finding warns`() {
        assertEquals(SrcuTimingVerdict.REPEATABLE_DELAY, delayed.analysis.verdict)
        assertEquals("Experimental fsnotify/SRCU timing anomaly", buildVerdict(delayedReport))
        assertTrue(buildSummary(delayedReport).startsWith("The optional experiment"))
        assertTrue(buildImpactItems(delayedReport).first().text.startsWith("The optional timing experiment"))
    }
    @Test fun `an established warning keeps the headline summary and impact`() {
        val report = delayedReport.copy(findings = listOf(NativeRootFinding("kernel_trace", "Kernel trace",
            "hit", "", NativeRootGroup.KERNEL, NativeRootFindingSeverity.WARNING)))
        assertEquals("2 native signal(s) need review", buildVerdict(report))
        assertTrue(buildSummary(report).startsWith("Only weaker"))
        assertTrue(buildImpactItems(report).first().text.startsWith("Isolated-process mount drift"))
    }
}
