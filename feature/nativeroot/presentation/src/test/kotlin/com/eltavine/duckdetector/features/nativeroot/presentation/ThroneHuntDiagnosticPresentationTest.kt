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
import com.eltavine.duckdetector.features.nativeroot.presentation.model.NativeRootHeaderFact
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ThroneHuntDiagnosticPresentationTest {
    private val mapper = NativeRootCardModelMapper()
    private val ready = NativeRootReport.loading().copy(
        stage = NativeRootStage.READY,
        cgroupAvailable = true,
        ksuSupercallAttempted = true,
        isolatedMountProbeAvailable = true,
        ksuThroneHuntAvailable = true,
        ksuThroneHuntStimulusApplied = true,
    )

    @Test
    @Suppress("DEPRECATION")
    fun `reported events are informational without runtime signals or root attribution`() {
        val report = ready.copy(
            ksuThroneHuntOpenCount = 3,
            ksuThroneHuntAccessCount = 3,
            ksuThroneHuntRawEventCount = 42,
        )
        val model = mapper.map(report)

        assertEquals(6, report.ksuThroneHuntHitCount)
        assertFalse(report.ksuThroneHuntDetected)
        assertTrue(report.detectedFamilies.isEmpty())
        assertEquals(DetectionSeverity.ALL_CLEAR, model.status.severity)
        assertEquals("No native root indicators", model.verdict)
        assertTrue(model.runtimeRows.isEmpty())
        assertEquals("Clean", model.headerFacts.single { it.fact == NativeRootHeaderFact.RUNTIME }.value)
        assertTrue(model.impactItems.none { it.text.contains("throne", ignoreCase = true) })
        val activity = model.scanRows.single { it.label == "Throne hunt" }
        val counters = model.scanRows.single { it.label == "Throne hunt counters" }
        assertEquals(DetectionSeverity.INFO, activity.status.severity)
        assertEquals(DetectionSeverity.INFO, counters.status.severity)
        assertEquals("open=3 access=3", activity.value)
        assertTrue(activity.detail!!.contains("diagnostic only"))
        assertTrue(counters.hiddenCopyText!!.contains("raw=42"))
        assertTrue(counters.hiddenCopyText.contains("interpretation=diagnostic_only"))
        assertTrue(counters.hiddenCopyText.contains("accessorAttribution=unverified"))

        val exported = model.toDetectorReport()
        assertEquals("No native root indicators", exported.verdict)
        val rows = exported.blocks.filterIsInstance<ReportBlock.Rows>().flatMap { it.rows }
        assertTrue(rows.any { it.label == "Throne hunt" && it.detail!!.contains("Unattributed") })
        assertTrue(rows.none { it.label == "KernelSU throne hunt" })
    }

    @Test
    fun `zero events do not make diagnostic rows clean`() {
        val model = mapper.map(ready)
        assertEquals("No directory events", model.scanRows.single { it.label == "Throne hunt" }.value)
        for (label in listOf("Throne hunt", "Throne hunt counters")) {
            assertEquals(DetectionSeverity.INFO, model.scanRows.single { it.label == label }.status.severity)
        }
    }

    @Test
    fun `unavailable diagnostic preserves failures without reducing independent root coverage`() {
        val model = mapper.map(ready.copy(
            ksuThroneHuntAvailable = false,
            ksuThroneHuntStimulusApplied = false,
            ksuThroneHuntFailureStage = "STIMULUS_FAILED",
            ksuThroneHuntOpenCount = 3,
            ksuThroneHuntAccessCount = 3,
        ))
        val row = model.scanRows.single { it.label == "Throne hunt" }
        assertEquals("STIMULUS_FAILED", row.value)
        assertEquals(DetectionSeverity.INFO, row.status.severity)
        assertTrue(row.hiddenCopyText!!.contains("open=3"))
        assertEquals(DetectionSeverity.ALL_CLEAR, model.status.severity)
    }

    @Test
    fun `independent danger findings retain their severity and runtime count`() {
        val model = mapper.map(ready.copy(
            ksuThroneHuntOpenCount = 3,
            ksuThroneHuntAccessCount = 3,
            findings = listOf(NativeRootFinding(
                id = "process_evidence", label = "Process evidence", value = "observed",
                detail = "Independent evidence", group = NativeRootGroup.PROCESS,
                severity = NativeRootFindingSeverity.DANGER,
            )),
        ))
        assertEquals(DetectionSeverity.DANGER, model.status.severity)
        assertEquals("1 runtime root signal(s)", model.verdict)
        assertEquals("1", model.headerFacts.single { it.fact == NativeRootHeaderFact.RUNTIME }.value)
        assertEquals("Process evidence", model.runtimeRows.single().label)
        assertEquals(DetectionSeverity.INFO, model.scanRows.single { it.label == "Throne hunt" }.status.severity)
    }
}
