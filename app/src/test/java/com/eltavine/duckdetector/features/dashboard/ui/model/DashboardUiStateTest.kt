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

package com.eltavine.duckdetector.features.dashboard.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import org.junit.Assert.assertEquals
import org.junit.Test

class DashboardUiStateTest {

    @Test
    fun `danger tee card status propagates to dashboard overview`() {
        val overview = buildDashboardOverview(
            contributions = listOf(
                DashboardDetectorContribution(
                    id = "tee",
                    title = "TEE",
                    status = DetectorStatus.danger(),
                    headline = "Attestation aligned; local probes need review",
                    summary = "ImportKey retained attestation narrative detected.",
                    ready = true,
                ),
                DashboardDetectorContribution(
                    id = "bootloader",
                    title = "Bootloader",
                    status = DetectorStatus.allClear(),
                    headline = "Locked",
                    summary = "Bootloader state is locked.",
                    ready = true,
                ),
            ),
        )

        assertEquals(DetectorStatus.danger(), overview.status)
        assertEquals("Danger", overview.headline)
        assertEquals("1", overview.metrics.single { it.label == "Danger" }.value)
    }

    @Test
    fun `danger contribution after warning still dominates dashboard overview`() {
        val overview = buildDashboardOverview(
            contributions = listOf(
                DashboardDetectorContribution(
                    id = "soter",
                    title = "Soter",
                    status = DetectorStatus.warning(),
                    headline = "Local review",
                    summary = "Soter local environment needs review.",
                    ready = true,
                ),
                DashboardDetectorContribution(
                    id = "tee",
                    title = "TEE",
                    status = DetectorStatus.danger(),
                    headline = "Attestation aligned; local probes need review",
                    summary = "UpdateSubcomponent stale TEE response persistence detected.",
                    ready = true,
                ),
            ),
        )

        assertEquals(DetectorStatus.danger(), overview.status)
        assertEquals("Danger", overview.headline)
        assertEquals("1", overview.metrics.single { it.label == "Danger" }.value)
    }

    @Test
    fun `top findings use compact finding detail when detector provides one`() {
        val findings = buildDashboardFindings(
            contributions = listOf(
                DashboardDetectorContribution(
                    id = "tee",
                    title = "TEE",
                    status = DetectorStatus.danger(),
                    headline = "Attestation aligned; local probes need review",
                    summary = "Grant self-domain certificate-chain split detected. Public: clean | Hidden: clean | Private: split.",
                    findingDetail = "Grant self-domain certificate chain diverged; open TEE details for stage diagnostics.",
                    ready = true,
                ),
            ),
        )

        assertEquals(
            "Grant self-domain certificate chain diverged; open TEE details for stage diagnostics.",
            findings.single().detail,
        )
    }
}
