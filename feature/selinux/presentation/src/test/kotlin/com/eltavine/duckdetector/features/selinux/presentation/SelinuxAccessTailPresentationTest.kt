/*
 * Copyright 2026 Duck Apps Contributor
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

package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxAccessTailPresentationTest {
    private fun report(positive: Boolean = false, denied: Boolean = false): SelinuxReport =
        SelinuxReport.loading().copy(
            stage = SelinuxStage.READY,
            mode = SelinuxMode.ENFORCING,
            methods = listOf(
                SelinuxCheckResult(
                    method = SelinuxOracle.XXKSU_ACCESS_TAIL.label,
                    oracle = SelinuxOracle.XXKSU_ACCESS_TAIL,
                    status = when {
                        denied -> "Permission limited"
                        positive -> "Ignored-tail rejection observed"
                        else -> "No ignored-tail rejection observed"
                    },
                    isSecure = if (positive) false else null,
                    permissionDenied = denied,
                ),
            ),
        )

    @Test fun `sole ignored tail positive is reflected in card and method details`() {
        val model = SelinuxCardModelMapper().map(report(positive = true))
        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals(DetectorStatus.danger(), model.methodRows.single().status)
        assertTrue(model.verdict.contains("/access ignored-tail anomaly"))
        assertTrue(model.summary.contains("SELinuxFS /access ignored-tail anomaly"))
        assertTrue(model.summary.contains(":ksu:"))
        assertFalse(model.summary.contains("looks internally consistent"))
        assertTrue(model.impactItems.any {
            it.status == DetectorStatus.danger() &&
                it.text.contains("/access parser/scanner mismatch")
        })
    }

    @Test fun `permission limited stays informational and never green`() {
        val model = SelinuxCardModelMapper().map(report(denied = true))
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), model.methodRows.single().status)
        assertFalse(model.methodRows.single().status == DetectorStatus.allClear())
        assertTrue(model.impactItems.none { it.text.contains("/access parser/scanner mismatch") })
    }

    @Test fun `no ignored tail rejection is informational not proof of a clean kernel`() {
        val model = SelinuxCardModelMapper().map(report())
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), model.methodRows.single().status)
        assertTrue(model.impactItems.none { it.text.contains("/access parser/scanner mismatch") })
    }

    @Test fun `unknown mode still describes the detected ignored tail anomaly`() {
        val model = SelinuxCardModelMapper().map(
            report(positive = true).copy(mode = SelinuxMode.UNKNOWN),
        )
        assertEquals(DetectorStatus.danger(), model.status)
        assertTrue(model.verdict.contains("/access ignored-tail anomaly"))
        assertTrue(model.summary.contains("/access ignored-tail anomaly"))
    }
}
