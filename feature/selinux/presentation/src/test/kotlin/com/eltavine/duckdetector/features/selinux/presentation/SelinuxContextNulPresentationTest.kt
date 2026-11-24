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

class SelinuxContextNulPresentationTest {
    private fun report(positive: Boolean = false, denied: Boolean = false): SelinuxReport =
        SelinuxReport.loading().copy(
            stage = SelinuxStage.READY,
            mode = SelinuxMode.ENFORCING,
            methods = listOf(
                SelinuxCheckResult(
                    method = SelinuxOracle.XXKSU_CONTEXT_NUL.label,
                    oracle = SelinuxOracle.XXKSU_CONTEXT_NUL,
                    status = when {
                        denied -> "Permission limited"
                        positive -> "NUL-tail rejection observed"
                        else -> "No NUL-tail rejection observed"
                    },
                    isSecure = if (positive) false else null,
                    permissionDenied = denied,
                ),
            ),
        )

    @Test fun `sole NUL tail positive matches its red verdict summary and impact`() {
        val card = SelinuxCardModelMapper().map(report(positive = true))
        assertEquals(DetectorStatus.danger(), card.status)
        assertEquals(DetectorStatus.danger(), card.methodRows.single().status)
        assertTrue(card.verdict.contains("/context NUL-tail anomaly"))
        assertTrue(card.summary.contains("/context NUL-tail anomaly"))
        assertTrue(card.summary.contains("first NUL"))
        assertFalse(card.summary.contains("looks internally consistent"))
        assertTrue(card.impactItems.any {
            it.status == DetectorStatus.danger() &&
                it.text.contains("/context parser/scanner mismatch")
        })
    }

    @Test fun `NUL tail permission limitation is informational not green`() {
        val card = SelinuxCardModelMapper().map(report(denied = true))
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), card.methodRows.single().status)
        assertTrue(card.impactItems.none { it.text.contains("/context parser/scanner mismatch") })
    }

    @Test fun `no NUL tail rejection is not an all clear proof`() {
        val card = SelinuxCardModelMapper().map(report())
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), card.methodRows.single().status)
        assertTrue(card.impactItems.none { it.text.contains("/context parser/scanner mismatch") })
    }

    @Test fun `unknown SELinux mode does not conceal a NUL tail positive`() {
        val card = SelinuxCardModelMapper().map(report(positive = true).copy(mode = SelinuxMode.UNKNOWN))
        assertEquals(DetectorStatus.danger(), card.status)
        assertTrue(card.verdict.contains("/context NUL-tail anomaly"))
        assertTrue(card.summary.contains("/context NUL-tail anomaly"))
    }
}
