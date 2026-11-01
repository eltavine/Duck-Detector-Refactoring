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
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.core.report.ReportBlock
import com.eltavine.duckdetector.features.nativeroot.domain.InitRcTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.InitRcTimingObservation
import com.eltavine.duckdetector.features.nativeroot.domain.InitRcTimingRound
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootStage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class InitRcTimingPresentationTest {
    @Test
    fun `every collection result remains supporting evidence`() {
        for (stage in InitRcTimingCollection.entries) {
            val row = initRcTimingRow(positive().copy(collection = stage))
            assertEquals(DetectionSeverity.INFO, row.status.severity)
            assertEquals(InfoKind.SUPPORT, row.status.infoKind)
        }
    }

    @Test
    fun `repeatable interaction and raw evidence reach the SDK export without attribution`() {
        val baseline = NativeRootReport.loading().copy(stage = NativeRootStage.READY)
        val mapper = NativeRootCardModelMapper()
        val model = mapper.map(baseline.copy(initRcTiming = positive()))
        val row = model.methodRows.single { it.label == "init.rc hook timing" }
        assertEquals("Repeatable interaction (experimental)", row.value)
        assertTrue(requireNotNull(row.detail).contains("0\t128000\t128000\t128000\t140800"))
        assertEquals(mapper.map(baseline).status, model.status)
        assertEquals(mapper.map(baseline).headerFacts, model.headerFacts)
        val exported = model.toDetectorReport().blocks.filterIsInstance<ReportBlock.Rows>()
            .single { it.title == "Methods" }.rows.single { it.label == row.label }
        assertEquals(row.value, exported.value)
        assertEquals(row.detail, exported.detail)
    }

    @Test
    fun `zero effect reports no repeatable interaction and a failed run retains diagnostics`() {
        val zero = positive().copy(rounds = List(32) { InitRcTimingRound(128000, 128000, 128000, 128000) })
        assertEquals("No repeatable interaction", initRcTimingRow(zero).value)
        val failed = initRcTimingRow(positive().copy(collection = InitRcTimingCollection.SYSCALL_FAILED, errorNumber = 13))
        assertEquals("Unavailable", failed.value)
        assertTrue(requireNotNull(failed.detail).contains("errno=13"))
    }

    private fun positive() = InitRcTimingObservation(
        collection = InitRcTimingCollection.COLLECTED, cpu = 2, cleanupCompleted = true,
        rounds = List(32) { InitRcTimingRound(128000, 128000, 128000, 140800) },
    )
}
