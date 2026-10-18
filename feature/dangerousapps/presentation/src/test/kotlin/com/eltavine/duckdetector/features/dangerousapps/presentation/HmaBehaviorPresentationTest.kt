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
import com.eltavine.duckdetector.features.dangerousapps.domain.*
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
        assertTrue(model.context.any { it.value.contains("10042") })
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
        assertTrue(model.context.any {
            it.label == HmaCheckKind.SECCOMP_UID_FILTER.label && it.value.contains("EBUSY")
        })
    }

    @Test fun `unavailable checks remain visible without raising a mismatch warning`() {
        val model = DangerousAppsCardModelMapper().map(report(HmaBehaviorCheck(
            HmaCheckKind.BROADCAST_RESULT_TO, HmaCheckState.UNAVAILABLE, "Service unavailable.")))
        assertTrue(model.context.any { it.value.contains("Unavailable") })
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
        assertTrue(model.context.any { it.value.contains("lower confidence") })
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
}
