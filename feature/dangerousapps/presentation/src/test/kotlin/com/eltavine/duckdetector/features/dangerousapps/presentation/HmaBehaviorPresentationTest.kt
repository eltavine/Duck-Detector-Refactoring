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
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.core.report.ReportBlock
import com.eltavine.duckdetector.features.dangerousapps.domain.*
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsHeaderFact
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HmaBehaviorPresentationTest {
    private fun report(check: HmaBehaviorCheck) = DangerousAppsReport(
        DangerousAppsStage.READY, DangerousPackageVisibility.FULL, 200, false, false,
        emptyList(), emptyList(), emptyList(), emptyList(), behaviorChecks = listOf(check))

    @Test fun `UID mismatch stays warning and exports numeric evidence without inventing a package`() {
        val model = DangerousAppsCardModelMapper().map(report(HmaBehaviorCheck(
            HmaCheckKind.UID_TASK_VISIBILITY, HmaCheckState.INCONSISTENT,
            "No visible package association.", uids = listOf(10042))))
        assertEquals(DetectionSeverity.WARNING, model.status.severity)
        assertEquals(null, model.hmaAlert)
        assertTrue(model.methodRows.any { it.detail.orEmpty().contains("10042") })
        assertEquals("Platform behavior mismatch observed", model.verdict)
    }

    @Test fun `seccomp getpriority evidence stays warning and exports its own check`() {
        val model = DangerousAppsCardModelMapper().map(report(HmaBehaviorCheck(
            HmaCheckKind.SECCOMP_UID_FILTER, HmaCheckState.INCONSISTENT,
            "seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER) returned EBUSY. Kernel 6.1.")))
        assertEquals(DetectionSeverity.WARNING, model.status.severity)
        assertEquals(null, model.hmaAlert)
        assertEquals("Platform behavior mismatch observed", model.verdict)
        assertTrue(model.summary.contains("seccomp getpriority"))
        assertTrue(model.methodRows.any {
            it.label == HmaCheckKind.SECCOMP_UID_FILTER.label && it.detail.orEmpty().contains("EBUSY")
        })
    }

    @Test fun `unavailable checks remain visible without raising a mismatch warning`() {
        val model = DangerousAppsCardModelMapper().map(report(HmaBehaviorCheck(
            HmaCheckKind.BROADCAST_RESULT_TO, HmaCheckState.UNAVAILABLE, "Service unavailable.")))
        assertTrue(model.methodRows.any { it.value.contains("Unavailable") })
        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertEquals("Behavior checks incomplete", model.verdict)
    }

    @Test fun `repeated missing callbacks remain a lower confidence warning without an HMA alert`() {
        val model = DangerousAppsCardModelMapper().map(report(HmaBehaviorCheck(
            HmaCheckKind.BROADCAST_RESULT_COMPLETION, HmaCheckState.TIMING_ANOMALY,
            "Repeated deadlines with passing controls.", packages = listOf("target"))))
        assertEquals(DetectionSeverity.WARNING, model.status.severity)
        assertEquals(null, model.hmaAlert)
        assertEquals("Repeated callback timeout asymmetry", model.verdict)
        assertTrue(model.methodRows.any { it.value.contains("lower confidence") })
        assertTrue(model.summary.contains("lower-confidence"))
    }

    @Test fun `unattributed seccomp setup trap remains informational and incomplete`() {
        val check = HmaSeccompUidPolicy.evaluate(HmaSeccompUidObservation(
            HmaSeccompUidEvidence.TRAPPED_INSTALL, 6, 6, 0, 0, -1, -1, false))
        val model = DangerousAppsCardModelMapper().map(report(check))
        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertEquals("Behavior checks incomplete", model.verdict)
        assertEquals(null, model.hmaAlert)
    }
    @Test fun `experimental UID permission findings stay informational without a hidden package`() {
        val check = HmaBehaviorCheck(HmaCheckKind.UID_PERMISSION_VISIBILITY,
            HmaCheckState.EXPERIMENTAL_ANOMALY, "UID 10043: android.permission.RECEIVE_BOOT_COMPLETED", uids = listOf(10043))
        val result = report(check)
        val model = DangerousAppsCardModelMapper().map(result)
        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertEquals(null, model.hmaAlert)
        assertEquals(0, result.hiddenCount)
        assertEquals("Experimental UID discrepancy observed", model.verdict)
        assertTrue(model.methodRows.any { it.detail.orEmpty().contains("RECEIVE_BOOT_COMPLETED") })
    }
    @Test fun `behavior row severity keeps mismatch timing failure and experimental scope distinct`() {
        for (state in HmaCheckState.entries) {
            val model = DangerousAppsCardModelMapper().map(report(HmaBehaviorCheck(
                HmaCheckKind.UID_TASK_VISIBILITY, state, "Measured scope", uids = listOf(10042))))
            val row = model.methodRows.single { it.label == HmaCheckKind.UID_TASK_VISIBILITY.label }
            val expected = when (state) {
                HmaCheckState.INCONSISTENT, HmaCheckState.TIMING_ANOMALY -> DetectorStatus.warning()
                HmaCheckState.CONSISTENT -> DetectorStatus.allClear()
                HmaCheckState.UNAVAILABLE -> DetectorStatus.info(InfoKind.ERROR)
                else -> DetectorStatus.info(InfoKind.SUPPORT)
            }
            assertEquals(state.name, expected, row.status)
            assertTrue(row.detail.orEmpty().contains("10042"))
            val exported = model.toDetectorReport().blocks.filterIsInstance<ReportBlock.Rows>()
                .single { it.title == "Detection methods" }.rows.single { it.label == row.label }
            assertEquals(row.detail, exported.detail)
        }
    }
    @Test fun `storage and inventory warnings remain visible without package hits`() {
        val source = report(HmaBehaviorCheck(HmaCheckKind.PACKAGE_INFO_EXCEPTION, HmaCheckState.CONSISTENT, "Control passed"))
            .copy(suspiciousSharedStorageDenied = true, suspiciousLowPmInventory = true)
        val model = DangerousAppsCardModelMapper().map(source)
        assertTrue(model.packageItems.isEmpty())
        assertEquals(DetectorStatus.warning(), model.context.single { it.label == "Shared storage baseline" }.status)
        assertEquals(DetectorStatus.warning(), model.context.single { it.label == "PackageManager" }.status)
    }

    @Test fun `missing behavior families do not become a completed runtime check`() {
        val mapper = DangerousAppsCardModelMapper()
        val base = report(HmaBehaviorCheck(HmaCheckKind.PACKAGE_INFO_EXCEPTION,
            HmaCheckState.CONSISTENT, "Control passed"))
            .copy(thanoxIpc = ThanoxIpcReport(ThanoxIpcState.NOT_OBSERVED))
        for (checks in listOf(emptyList(), base.behaviorChecks)) {
            val fact = mapper.map(base.copy(behaviorChecks = checks)).headerFacts
                .single { it.fact == DangerousAppsHeaderFact.RUNTIME }
            assertEquals("Incomplete", fact.value)
            assertEquals(DetectorStatus.info(InfoKind.SUPPORT), fact.status)
        }
        val complete = mapper.map(base.copy(behaviorChecks = HmaCheckKind.entries.map {
            HmaBehaviorCheck(it, HmaCheckState.CONSISTENT, "Control passed")
        })).headerFacts.single { it.fact == DangerousAppsHeaderFact.RUNTIME }
        assertEquals("0 signal(s)", complete.value)
        assertEquals(DetectorStatus.allClear(), complete.status)
    }
}
