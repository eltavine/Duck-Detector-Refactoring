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

package com.eltavine.duckdetector.features.tee.data.report

import com.eltavine.duckdetector.features.tee.domain.TeeReport
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeSoterAnomaly
import com.eltavine.duckdetector.features.tee.domain.TeeSoterAnomalyKind
import com.eltavine.duckdetector.features.tee.domain.TeeSoterState
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TeeReportReducerSoterTest {

    private val reducer = TeeReportReducer()

    @Test
    fun `fabricated soter signature is a local failure without changing the attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                soter = availableSoter(
                    TeeSoterAnomaly(TeeSoterAnomalyKind.D_SOTER_ZERO_SIGNATURE, TeeSignalLevel.FAIL, "all-zero signature in ASK"),
                    TeeSoterAnomaly(TeeSoterAnomalyKind.D_SOTER_ZERO_CPU_ID, TeeSignalLevel.WARN, "all-zero cpu_id in ASK"),
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertEquals(TeeSignalLevel.FAIL, report.supplementaryReviewLevel)
        assertEquals(
            "Soter replies need review: all-zero signature in ASK; all-zero cpu_id in ASK. " +
                "Attestation and trust-path checks still aligned.",
            report.summary,
        )
        assertEquals(TeeSignalLevel.FAIL, soterRowLevel(report))
    }

    @Test
    fun `relay identity alone stays a local warning`() {
        val report = reducer.reduce(
            baseArtifacts(
                soter = availableSoter(
                    TeeSoterAnomaly(TeeSoterAnomalyKind.KNOWN_RELAY_CPU_ID, TeeSignalLevel.WARN, "relay cpu_id in ASK"),
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(TeeSignalLevel.WARN, report.supplementaryReviewLevel)
        assertEquals(TeeSignalLevel.WARN, soterRowLevel(report))
        assertTrue(report.signals.any { it.label == "Signals" && it.value.contains("1 local") })
    }

    @Test
    fun `available soter without anomalies passes without a local indicator`() {
        val report = reducer.reduce(baseArtifacts(soter = availableSoter()))

        assertEquals(0, report.supplementaryIndicatorCount)
        assertEquals(TeeSignalLevel.PASS, soterRowLevel(report))
    }

    private fun availableSoter(vararg anomalies: TeeSoterAnomaly) = TeeSoterState(
        serviceReachable = true,
        keyPrepared = true,
        signSessionAvailable = true,
        available = true,
        anomalies = anomalies.toList(),
        summary = "Soter ASK/AuthKey/initSigh calls succeeded.",
    )

    private fun soterRowLevel(report: TeeReport): TeeSignalLevel =
        report.sections.single { it.title == "Checks" }.items.single { it.title == "Soter" }.level
}
