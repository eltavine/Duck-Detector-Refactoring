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

package com.eltavine.duckdetector.features.dashboard.presentation.model

import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.core.scan.DetectorSummary
import org.junit.Assert.assertEquals
import org.junit.Test

class DashboardUiStateTest {

    @Test
    fun `danger tee card status propagates to dashboard overview`() {
        val overview = buildDashboardOverview(
            contributions = listOf(
                DetectorSummary(
                    id = DetectorId("tee"),
                    title = "TEE",
                    status = DetectorStatus.danger(),
                    headline = "Attestation aligned; local probes need review",
                    summary = "ImportKey retained attestation narrative detected.",
                    ready = true,
                ),
                DetectorSummary(
                    id = DetectorId("bootloader"),
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
                DetectorSummary(
                    id = DetectorId("soter"),
                    title = "Soter",
                    status = DetectorStatus.warning(),
                    headline = "Local review",
                    summary = "Soter local environment needs review.",
                    ready = true,
                ),
                DetectorSummary(
                    id = DetectorId("tee"),
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
                DetectorSummary(
                    id = DetectorId("tee"),
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
        assertEquals(DetectorId("tee"), findings.single().detectorId)
    }
    @Test
    fun `cards order by severity then title`() {
        fun summary(id: String, title: String, status: DetectorStatus) = DetectorSummary(
            id = DetectorId(id),
            title = title,
            status = status,
            headline = "",
            summary = "",
            ready = true,
        )

        val order = dashboardCardOrder(
            listOf(
                summary("clear_b", "B clear", DetectorStatus.allClear()),
                summary("support", "Support", DetectorStatus.info(InfoKind.SUPPORT)),
                summary("clear_a", "A clear", DetectorStatus.allClear()),
                summary("error", "Error", DetectorStatus.info(InfoKind.ERROR)),
                summary("warning", "Warning", DetectorStatus.warning()),
                summary("danger", "Danger", DetectorStatus.danger()),
            ),
        )

        assertEquals(
            listOf("danger", "warning", "error", "support", "clear_a", "clear_b").map(::DetectorId),
            order,
        )
    }
    @Test
    fun `overview exposes the typed outcome its wording describes`() {
        fun summary(id: String, status: DetectorStatus, ready: Boolean) = DetectorSummary(
            id = DetectorId(id),
            title = id,
            status = status,
            headline = "",
            summary = "",
            ready = ready,
        )

        val overview = buildDashboardOverview(
            contributions = listOf(
                summary("warning_one", DetectorStatus.warning(), ready = true),
                summary("danger_one", DetectorStatus.danger(), ready = true),
                summary("clear_one", DetectorStatus.allClear(), ready = false),
            ),
        )

        assertEquals(OverviewVerdict.DANGER, overview.verdict)
        assertEquals("Danger", overview.headline)
        assertEquals(false, overview.titleDescribesCompletedScan)
    }
}
