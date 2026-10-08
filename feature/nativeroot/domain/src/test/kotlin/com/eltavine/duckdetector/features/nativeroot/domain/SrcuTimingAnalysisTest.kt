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

package com.eltavine.duckdetector.features.nativeroot.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SrcuTimingAnalysisTest {
    private fun window(delay: Long, count: Int = 16) = SrcuTimingWindow(1000, 100000, false,
        List(count) { SrcuCloseSample(1000L + it * 1000, 1000L + it * 1000 + delay, SrcuCloseStage.OK) })
    private fun observation(stimulus: Long, sequential: Long = 100) = SrcuTimingObservation(
        SrcuTimingCollection.COLLECTED,
        List(ROUND_COUNT) { SrcuTimingRound(window(100), window(stimulus), window(sequential)) },
        cleanupCompleted = true,
    )
    @Test fun `replicated delay is supporting warning without adding a tool identity`() {
        val result = observation(5000)
        assertEquals(SrcuTimingVerdict.REPEATABLE_DELAY, result.analysis.verdict)
        val report = NativeRootReport.loading().copy(stage = NativeRootStage.READY, srcuTiming = result)
        assertTrue(report.hasWarningFindings)
        assertFalse(report.hasDangerFindings)
        assertFalse(report.kernelSuDetected)
        assertTrue(report.detectedFamilies.isEmpty())
        assertTrue(report.directFindings.isEmpty())
    }
    @Test fun `failed requested experiment reduces shared report coverage`() {
        val report = NativeRootReport.loading().copy(stage = NativeRootStage.READY,
            srcuTiming = SrcuTimingObservation(SrcuTimingCollection.TIMED_OUT))
        assertTrue(report.hasReducedCoverage())
    }
    @Test fun `equal distributions do not claim a clean device`() {
        assertEquals(SrcuTimingVerdict.NOT_OBSERVED, observation(100).analysis.verdict)
    }
    @Test fun `a small difference with zero MAD is below the relative noise floor`() {
        assertEquals(SrcuTimingVerdict.NOT_OBSERVED, observation(105).analysis.verdict)
    }
    @Test fun `sequential elevation defeats the overlap interpretation`() {
        assertEquals(SrcuTimingVerdict.INCONCLUSIVE, observation(5000, 5000).analysis.verdict)
    }
    @Test fun `an isolated right tail is inconclusive rather than a warning`() {
        val regular = observation(100)
        val result = regular.copy(rounds = regular.rounds.toMutableList().apply {
            this[0] = this[0].copy(stimulated = window(5000))
        })
        assertEquals(SrcuTimingVerdict.INCONCLUSIVE, result.analysis.verdict)
    }
    @Test fun `replication is required in every temporal block`() {
        val candidate = observation(5000)
        val result = candidate.copy(rounds = candidate.rounds.mapIndexed { index, round ->
            if (index < 3) round.copy(stimulated = window(100)) else round
        })
        assertEquals(SrcuTimingVerdict.INCONCLUSIVE, result.analysis.verdict)
    }
    @Test fun `missing overlap and exhausted sample quotas cannot read as absence`() {
        val candidate = observation(5000)
        for (bad in listOf(window(100, 2), window(100).copy(saturated = true),
            window(100).copy(beginNanos = 90000))) {
            val result = candidate.copy(rounds = candidate.rounds.map { it.copy(stimulated = bad) })
            assertEquals(SrcuTimingVerdict.INCONCLUSIVE, result.analysis.verdict)
        }
    }
    @Test fun `failed native samples cannot read as absence`() {
        val candidate = observation(5000)
        val bad = window(100).copy(samples = listOf(SrcuCloseSample(0, 0, SrcuCloseStage.WATCH_FAILED, 13)))
        assertEquals(SrcuTimingVerdict.INCONCLUSIVE, candidate.copy(
            rounds = candidate.rounds.map { it.copy(stimulated = bad) }).analysis.verdict)
    }
    @Test fun `every collection failure and unknown cleanup remains unassessed`() {
        for (state in SrcuTimingCollection.entries.filter { it != SrcuTimingCollection.COLLECTED }) {
            assertEquals(SrcuTimingVerdict.NOT_EVALUATED, observation(5000).copy(collection = state).analysis.verdict)
        }
        assertEquals(SrcuTimingVerdict.NOT_EVALUATED, observation(5000).copy(cleanupCompleted = false).analysis.verdict)
        assertEquals(SrcuTimingVerdict.INCONCLUSIVE, observation(5000).copy(rounds = emptyList()).analysis.verdict)
    }
}
