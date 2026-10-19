package com.eltavine.duckdetector.features.nativeroot.domain

import org.junit.Assert.assertEquals
import org.junit.Test

class KernelSuTimingObservationTest {
    private val positive = KernelSuTimingAnalysis(
        KernelSuTimingDistance(10000, 0, 10000, 10000),
        KernelSuTimingSimilarity(1.0, 0.0, 1.0, 1.0, 1.0, 10.0, 20.0),
    )
    private val negative = positive.copy(distance = KernelSuTimingDistance(10000, 10000, 10000, 0))
    private fun core(cpu: Int, rounds: List<KernelSuTimingAnalysis>) = KernelSuTimingCoreAttempt(
        cpu, cpu, KernelSuTimingCoreStatus.MEASURED, rounds,
    )
    private fun observation(vararg attempts: KernelSuTimingCoreAttempt) = KernelSuTimingObservation(
        collection = KernelSuTimingCollection.COLLECTED,
        preflight = KernelSuTimingPreflight.fromFrequencies(listOf(100uL, 10000uL)),
        enumeratedCpus = attempts.indices.toList(),
        attempts = attempts.toList(),
        counterFrequencyHz = 19200000uL,
        cleanupCompleted = true,
    )

    @Test fun `three positives must occur on the same core`() {
        assertEquals(KernelSuTimingVerdict.REPEATED_PATTERN,
            observation(core(0, List(3) { positive })).verdict)
        assertEquals(KernelSuTimingVerdict.INCONCLUSIVE,
            observation(core(0, listOf(positive, positive)), core(1, listOf(positive))).verdict)
        assertEquals(KernelSuTimingVerdict.NOT_OBSERVED,
            observation(core(0, listOf(positive, positive, negative))).verdict)
    }

    @Test fun `noninteractive abort never reuses an earlier result`() {
        val incomplete = observation(core(0, listOf(positive, positive)))
            .copy(collection = KernelSuTimingCollection.NONINTERACTIVE)
        assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, incomplete.verdict)
        assertEquals(KernelSuTimingVerdict.REPEATED_PATTERN,
            observation(core(0, List(3) { positive })).verdict)
        assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, incomplete.verdict)
    }

    @Test fun `transport or execution failure cannot carry a confirmed verdict`() {
        val confirmed = observation(core(0, List(3) { positive }))
        for (state in listOf(KernelSuTimingCollection.WORKER_DIED, KernelSuTimingCollection.PROTOCOL_ERROR,
            KernelSuTimingCollection.TIMED_OUT, KernelSuTimingCollection.CANCELLED)) {
            assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, confirmed.copy(collection = state).verdict)
        }
    }

    @Test fun `coverage and cleanup failures cannot report absence`() {
        val clean = observation(core(0, listOf(negative)))
        assertEquals(KernelSuTimingVerdict.NOT_OBSERVED, clean.verdict)
        assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, clean.copy(cleanupCompleted = false).verdict)
        assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, clean.copy(enumeratedCpus = listOf(0, 1)).verdict)
        for (status in KernelSuTimingCoreStatus.entries.filter { it != KernelSuTimingCoreStatus.MEASURED }) {
            assertEquals(KernelSuTimingVerdict.INCONCLUSIVE,
                clean.copy(attempts = listOf(clean.attempts.single().copy(status = status))).verdict)
        }
        assertEquals(KernelSuTimingVerdict.INCONCLUSIVE,
            clean.copy(attempts = listOf(clean.attempts.single().copy(actualCpu = 1))).verdict)
    }

    @Test fun `preflight uses unsorted tick count pairs and inclusive minimum boundary`() {
        val accepted = KernelSuTimingPreflight.fromFrequencies(listOf(999uL, 5000uL, 135uL, 5000uL))
        assertEquals(KernelSuTimingPreflightStatus.ACCEPTED, accepted.status)
        assertEquals(135uL, accepted.minimumTicks)
        assertEquals(KernelSuTimingPreflightStatus.EXCESSIVE_MINIMUM,
            KernelSuTimingPreflight.fromFrequencies(listOf(136uL, 10000uL)).status)
    }

    @Test fun `preflight rejects malformed or excessive histogram shapes`() {
        for (frequencies in listOf(emptyList(), listOf(1uL), listOf(1uL, 0uL),
            listOf(1uL, 10001uL), listOf(1uL, 5000uL, 1uL, 5000uL))) {
            assertEquals(KernelSuTimingPreflightStatus.MALFORMED,
                KernelSuTimingPreflight.fromFrequencies(frequencies).status)
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
