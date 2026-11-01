// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.features.dangerousapps.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.core.report.ReportBlock
import com.eltavine.duckdetector.features.dangerousapps.domain.*
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsHeaderFact
import org.junit.Assert.*
import org.junit.Test

class ThanoxIpcPresentationTest {
    private val mapper = DangerousAppsCardModelMapper()

    @Test fun `matching runtime interface does not become an installed or hidden app`() {
        val report = report(ThanoxIpcState.MATCHED)
        val model = mapper.map(report)
        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals(DetectorStatus.warning(), model.headerFacts.single { it.fact == DangerousAppsHeaderFact.RUNTIME }.status)
        assertEquals("Thanox-compatible runtime service observed", model.verdict)
        assertEquals(0, report.detectedCount)
        assertEquals(0, report.hiddenCount)
        assertTrue(model.packageItems.isEmpty())
        assertNull(model.hmaAlert)
        assertNull(model.packageSectionSeverity)
        assertTrue(model.summary.contains("does not establish installation"))
        val blocks = model.toDetectorReport().blocks.filterIsInstance<ReportBlock.Verbatim>()
        val methods = model.toDetectorReport().blocks.filterIsInstance<ReportBlock.Rows>()
            .single { it.title == "Detection methods" }.rows
        assertTrue(methods.single { it.label == "Thanox runtime IPC" }.detail.orEmpty().contains("Fixture reply"))
        assertEquals(DetectorStatus.warning(), model.methodRows.single { it.label == "Thanox runtime IPC" }.status)
        assertFalse(blocks.any { it.title == "Detected Packages" || it.title.startsWith("HMA Alert") })
    }

    @Test fun `bad or unavailable IPC evidence is incomplete instead of detected or clean`() {
        for (state in listOf(ThanoxIpcState.INCONCLUSIVE, ThanoxIpcState.UNAVAILABLE, ThanoxIpcState.NOT_COLLECTED)) {
            val model = mapper.map(report(state))
            assertEquals(DetectorStatus.info(InfoKind.SUPPORT), model.status)
            assertEquals("Thanox IPC check incomplete", model.verdict)
            assertTrue(model.packageItems.isEmpty())
            assertNull(model.hmaAlert)
        }
    }

    @Test fun `unhandled transaction can complete with no runtime signal`() {
        assertEquals(DetectorStatus.allClear(), mapper.map(report(ThanoxIpcState.NOT_OBSERVED)).status)
    }

    @Test fun `independent hidden package retains danger even when IPC is inconclusive`() {
        val target = DangerousAppsCatalog.targets.first()
        val finding = DangerousAppFinding(target, listOf(DangerousDetectionMethod(DangerousDetectionMethodKind.OPEN_APK_FD)))
        val model = mapper.map(report(ThanoxIpcState.INCONCLUSIVE).copy(
            findings = listOf(finding), hiddenFromPackageManager = listOf(finding),
        ))
        assertEquals(DetectorStatus.danger(), model.status)
        assertNotNull(model.hmaAlert)
    }

    private fun report(state: ThanoxIpcState) = DangerousAppsReport(
        stage = DangerousAppsStage.READY,
        packageVisibility = DangerousPackageVisibility.FULL,
        packageManagerVisibleCount = 500,
        suspiciousLowPmInventory = false,
        suspiciousSharedStorageDenied = false,
        targets = DangerousAppsCatalog.targets,
        findings = emptyList(), hiddenFromPackageManager = emptyList(),
        probesRan = listOf(DangerousDetectionMethodKind.THANOX_IPC),
        packageChangeHistory = PackageChangeHistory(PackageChangeHistoryState.AVAILABLE),
        thanoxIpc = ThanoxIpcReport(state, detail = "Fixture reply"),
    )
}
