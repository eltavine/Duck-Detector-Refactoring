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

package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxFdReusePresentationTest {
    private fun report(detected: Boolean): SelinuxReport = SelinuxReport.loading().copy(
        stage = SelinuxStage.READY,
        mode = SelinuxMode.ENFORCING,
        methods = listOf(
            SelinuxCheckResult(
                method = SelinuxOracle.XXKSU_FD_REUSE.label,
                status = if (detected) "Early return observed" else "No FD bypass observed",
                isSecure = if (detected) false else null,
                permissionDenied = false,
                details = "app_zygote same-FD raw write errno controls",
                oracle = SelinuxOracle.XXKSU_FD_REUSE,
            ),
        ),
    )

    @Test fun `controlled early return is danger in card and method row`() {
        val model = SelinuxCardModelMapper().map(report(true))
        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals(DetectorStatus.danger(), model.methodRows.single().status)
        assertTrue(model.methodRows.single().label.startsWith("xxksu "))
        assertTrue(model.verdict.contains("transaction-state anomaly"))
        assertTrue(model.verdict.contains("xxksu"))
        assertTrue(model.summary.contains("same-FD early-return anomaly for a ksu/ksu_file candidate context"))
        assertTrue(model.impactItems.any {
            it.status == DetectorStatus.danger() && it.text.contains("same-FD")
        })
    }

    @Test fun `stock like result is informational not an all clear claim`() {
        val model = SelinuxCardModelMapper().map(report(false))
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), model.methodRows.single().status)
        assertTrue(model.impactItems.none { it.text.contains("same-FD") })
    }
}
