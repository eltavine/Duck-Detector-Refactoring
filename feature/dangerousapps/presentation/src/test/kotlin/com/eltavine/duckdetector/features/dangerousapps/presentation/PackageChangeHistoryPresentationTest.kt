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

package com.eltavine.duckdetector.features.dangerousapps.presentation

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.report.ReportBlock
import com.eltavine.duckdetector.features.dangerousapps.domain.*
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsHeaderFact
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PackageChangeHistoryPresentationTest {
    private val target = DangerousAppsCatalog.targets.first { it.packageName == "com.tsng.hidemyapplist" }
    private val mapper = DangerousAppsCardModelMapper()
    private fun report(history: PackageChangeHistory) = DangerousAppsReport(
        stage = DangerousAppsStage.READY,
        packageVisibility = DangerousPackageVisibility.FULL,
        packageManagerVisibleCount = 200,
        suspiciousLowPmInventory = false,
        suspiciousSharedStorageDenied = false,
        targets = listOf(target),
        findings = emptyList(),
        hiddenFromPackageManager = emptyList(),
        probesRan = emptyList(),
        packageChangeHistory = history,
        thanoxIpc = ThanoxIpcReport(ThanoxIpcState.NOT_OBSERVED),
    )
    private fun matchedHistory() = PackageChangeHistory(
        PackageChangeHistoryState.AVAILABLE, listOf(target), 42,
    )

    @Test fun `removed package history stays informational without installed or hidden hits`() {
        val report = report(matchedHistory())
        val model = mapper.map(report)
        assertEquals(0, report.detectedCount)
        assertEquals(0, report.hiddenCount)
        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertEquals("Package change history observed", model.verdict)
        assertTrue(model.summary.contains("normal removal"))
        assertEquals(null, model.hmaAlert)
        assertEquals(null, model.packageSectionSeverity)
        assertTrue(model.packageItems.isEmpty())
        assertTrue(model.headerFacts.filter { it.fact in setOf(DangerousAppsHeaderFact.HITS,
            DangerousAppsHeaderFact.HIDDEN) }.all { it.value == "0" })
        val history = requireNotNull(model.packageHistory)
        assertEquals(target.packageName, history.packages.single().packageName)
        assertTrue(history.summary.contains("42"))
        assertTrue(history.summary.contains("event type and time are not provided"))
        assertTrue(history.summary.contains("cannot establish current installation"))
    }

    @Test fun `export keeps history out of detected package and HMA blocks`() {
        val exported = mapper.map(report(matchedHistory())).toDetectorReport()
        val blocks = exported.blocks.filterIsInstance<ReportBlock.Verbatim>()
        val history = blocks.single { it.title == "Package Changes Since Boot" }
        assertTrue(history.lines.any { target.packageName in it })
        assertTrue(history.lines.any { "current installation unconfirmed" in it })
        assertFalse(blocks.any { it.title == "Detected Packages" || it.title.startsWith("HMA Alert") })
    }

    @Test fun `missing query and all failure states remain incomplete information`() {
        PackageChangeHistoryState.entries.filter { it != PackageChangeHistoryState.AVAILABLE }.forEach { state ->
            val model = mapper.map(report(PackageChangeHistory(state)))
            assertEquals(DetectionSeverity.INFO, model.status.severity)
            assertEquals("Package change history incomplete", model.verdict)
            assertTrue(requireNotNull(model.packageHistory).packages.isEmpty())
            assertEquals(null, model.hmaAlert)
        }
    }

    @Test fun `null and filtered responses describe limited visibility without inventing history`() {
        listOf(null, 12).forEach { sequence ->
            val model = mapper.map(report(PackageChangeHistory(
                PackageChangeHistoryState.AVAILABLE, sequenceNumber = sequence)))
            val history = requireNotNull(model.packageHistory)
            assertTrue(history.packages.isEmpty())
            assertTrue(history.summary.contains("0 monitored package(s)"))
            assertTrue(history.summary.contains("may be filtered"))
            assertEquals(DetectionSeverity.ALL_CLEAR, model.status.severity)
        }
    }

    @Test fun `history preserves restricted inventory and incomplete behavior conclusions`() {
        val base = report(matchedHistory())
        val restricted = mapper.map(base.copy(packageVisibility = DangerousPackageVisibility.RESTRICTED))
        assertEquals("Inventory visibility limited", restricted.verdict)
        assertEquals(1, restricted.packageHistory?.packages?.size)
        val partial = mapper.map(base.copy(behaviorChecks = listOf(HmaBehaviorCheck(
            HmaCheckKind.PACKAGE_INFO_EXCEPTION, HmaCheckState.UNAVAILABLE, "Unavailable."))))
        assertEquals("Behavior checks incomplete", partial.verdict)
        assertEquals(1, partial.packageHistory?.packages?.size)
    }

    @Test fun `current installed findings retain warning severity independently of history`() {
        val finding = DangerousAppFinding(target,
            listOf(DangerousDetectionMethod(DangerousDetectionMethodKind.PACKAGE_MANAGER)))
        val model = mapper.map(report(matchedHistory()).copy(findings = listOf(finding)))
        assertEquals(DetectionSeverity.WARNING, model.status.severity)
        assertEquals("1 risky package(s) surfaced", model.verdict)
        assertEquals(1, model.packageItems.size)
        assertEquals(1, model.packageHistory?.packages?.size)
        assertEquals(null, model.hmaAlert)
    }

    @Test fun `loading and failed cards have no fabricated history section`() {
        listOf(DangerousAppsReport.loading(listOf(target)),
            DangerousAppsReport.failed(listOf(target), "Unavailable.")).forEach { report ->
            assertEquals(null, mapper.map(report).packageHistory)
        }
    }
}
