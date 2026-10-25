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
import org.junit.Test

class KernelSuTimingObservationTest {
    private val positive = KernelSuTimingClassifier.summarize(listOf(10uL, 20uL, 10uL, 10uL, 10uL, 10uL)
        .map { tick -> List(10000) { tick } })
    private val negative = positive.copy(distance = KernelSuTimingDistance(10000, 10000, 10000, 0))
    private val cpus = KernelSuTimingCpuSnapshot(listOf(0, 1), listOf(0, 1), listOf(0, 1))
    private val outcome = KernelSuTimingSyscallSummary(mapOf(-22L to 10000))
    private fun core(cpu: Int, rounds: List<KernelSuTimingAnalysis>) = KernelSuTimingCoreAttempt(
        cpu, cpu, KernelSuTimingCoreStatus.MEASURED, rounds,
        KernelSuTimingPreflight.fromFrequencies(listOf(100uL, 10000uL)),
        List(rounds.size + 1) { index -> KernelSuTimingWindowEvidence(cpus, cpus, cpus.allowed.orEmpty(),
            List(if (index == 0) 1 else 6) { outcome }, 19200000uL) })
    private fun observation(vararg attempts: KernelSuTimingCoreAttempt) = KernelSuTimingObservation(
        collection = KernelSuTimingCollection.COLLECTED, initialCpus = cpus, attempts = attempts.toList(),
        finalCpus = cpus, cleanupCompleted = true)

    @Test fun `positive requires three valid rounds on the same CPU`() {
        assertEquals(KernelSuTimingVerdict.REPEATED_PATTERN, observation(core(0, List(3) { positive })).verdict)
        assertEquals(KernelSuTimingVerdict.INCONCLUSIVE,
            observation(core(0, listOf(positive, positive)), core(1, listOf(positive))).verdict)
        assertEquals(KernelSuTimingVerdict.NOT_OBSERVED,
            observation(core(0, listOf(positive, positive, negative)), core(1, listOf(negative))).verdict)
    }

    @Test fun `transport cancellation deadline and cleanup failures cannot confirm`() {
        val confirmed = observation(core(0, List(3) { positive }))
        for (state in listOf(KernelSuTimingCollection.WORKER_DIED, KernelSuTimingCollection.PROTOCOL_ERROR,
            KernelSuTimingCollection.TIMED_OUT, KernelSuTimingCollection.CANCELLED)) {
            assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, confirmed.copy(collection = state).verdict)
        }
        assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, confirmed.copy(cleanupCompleted = false).verdict)
    }

    @Test fun `coverage status eligibility and histogram support failures cannot report absence`() {
        val clean = observation(core(0, listOf(negative)), core(1, listOf(negative)))
        assertEquals(KernelSuTimingVerdict.NOT_OBSERVED, clean.verdict)
        assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, clean.copy(attempts = clean.attempts.take(1)).verdict)
        assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, clean.copy(finalCpus = cpus.copy(online = listOf(0))).verdict)
        for (status in KernelSuTimingCoreStatus.entries.filter { it != KernelSuTimingCoreStatus.MEASURED }) {
            assertEquals(KernelSuTimingVerdict.INCONCLUSIVE,
                clean.copy(attempts = listOf(clean.attempts[0].copy(status = status), clean.attempts[1])).verdict)
        }
        val unsupported = negative.copy(support = emptyList())
        assertEquals(KernelSuTimingVerdict.INCONCLUSIVE,
            observation(core(0, listOf(unsupported)), core(1, listOf(negative))).verdict)
        val contaminated = core(0, listOf(negative)).let { core -> core.copy(windows = core.windows.map {
            it.copy(outcomes = List(it.outcomes.size) { KernelSuTimingSyscallSummary(mapOf(-1L to 10000)) }) }) }
        assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, observation(contaminated, core(1, listOf(negative))).verdict)
    }

    @Test fun `preflight preserves the inclusive minimum tick boundary and diagnostics`() {
        val accepted = KernelSuTimingPreflight.fromFrequencies(listOf(999uL, 5000uL, 135uL, 5000uL))
        assertEquals(KernelSuTimingPreflightStatus.ACCEPTED, accepted.status)
        assertEquals(135uL, accepted.minimumTicks)
        val rejected = KernelSuTimingPreflight.fromFrequencies(listOf(999uL, 5000uL, 136uL, 5000uL))
        assertEquals(KernelSuTimingPreflightStatus.EXCESSIVE_MINIMUM, rejected.status)
        assertEquals(136uL, rejected.minimumTicks)
        assertEquals(2, rejected.binCount)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `accepted summaries cannot bypass the minimum tick gate`() {
        KernelSuTimingPreflight(KernelSuTimingPreflightStatus.ACCEPTED, 1, 136uL)
    }

    @Test fun `preflight rejects malformed or excessive histogram shapes`() {
        for (frequencies in listOf(emptyList(), listOf(1uL), listOf(1uL, 0uL),
            listOf(1uL, 10001uL), listOf(1uL, 5000uL, 1uL, 5000uL))) {
            assertEquals(KernelSuTimingPreflightStatus.MALFORMED, KernelSuTimingPreflight.fromFrequencies(frequencies).status)
        }
        fun frequencies(bins: Int) = (0 until bins).flatMap {
            listOf(it.toULong(), if (it == 0) (10001 - bins).toULong() else 1uL)
        }
        assertEquals(KernelSuTimingPreflightStatus.ACCEPTED,
            KernelSuTimingPreflight.fromFrequencies(frequencies(750)).status)
        assertEquals(KernelSuTimingPreflightStatus.TOO_MANY_BINS,
            KernelSuTimingPreflight.fromFrequencies(frequencies(751)).status)
    }
}
