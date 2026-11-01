package com.eltavine.duckdetector.features.nativeroot.domain

import org.junit.Assert.assertEquals
import org.junit.Test

class KernelSuWrapperLeakObservationTest {
    private fun observation(growth: List<Long> = listOf(256, 256, 256)):
        KernelSuWrapperLeakObservation {
        var count = 10000L
        val points = mutableListOf(WrapperFileNrPoint(count, 0))
        growth.forEach { increase ->
            points += WrapperFileNrPoint(count, 0) // idle
            points += WrapperFileNrPoint(count, 0) // direct
            count += increase
            points += WrapperFileNrPoint(count, 0) // reopen
            points += WrapperFileNrPoint(count, 0) // direct
        }
        points += WrapperFileNrPoint(count, 0)
        return KernelSuWrapperLeakObservation(WrapperLeakCollection.COLLECTED, 0, 3, 768, points)
    }
    @Test fun `three bounded increases correlate but do not identify root`() {
        val positive = observation()
        assertEquals(WrapperLeakVerdict.REPEATED_GROWTH, positive.verdict)
        val report = NativeRootReport.loading().copy(stage = NativeRootStage.READY, wrapperLeak = positive)
        assertEquals(true, report.hasWarningFindings)
        assertEquals(false, report.rootDetected)
        assertEquals(false, report.kernelSuDetected)
        assertEquals(WrapperLeakVerdict.NO_PATTERN, observation(listOf(0, 0, 0)).verdict)
    }
    @Test fun `single spikes falling counts oversized growth and weak signals stay inconclusive`() {
        for (growth in listOf(listOf(768L, 0, 0), listOf(0L, 256, 256), listOf(-256L, -256, -256),
            listOf(512L, 512, 512), listOf(128L, 128, 128)))
            assertEquals(WrapperLeakVerdict.INCONCLUSIVE, observation(growth).verdict)
    }
    @Test fun `controls sampling noise and loss of persistence veto the pattern`() {
        val positive = observation()
        for (index in listOf(0, 1, 3, 4, 5, 7, 8, 9, 11, 12)) {
            val points = positive.points.toMutableList()
            points[index + 1] = points[index + 1].let { it.copy(median = it.median + 100) }
            assertEquals(WrapperLeakVerdict.INCONCLUSIVE, positive.copy(points = points).verdict)
        }
        assertEquals(WrapperLeakVerdict.INCONCLUSIVE,
            positive.copy(points = positive.points.map { it.copy(spread = 65) }).verdict)
        assertEquals(WrapperLeakVerdict.INCONCLUSIVE,
            positive.copy(points = positive.points.dropLast(1) + positive.points.first()).verdict)
    }
    @Test fun `failure incomplete protocol and cleanup can never report no pattern or a match`() {
        val positive = observation()
        for (state in WrapperLeakCollection.entries.filter { it != WrapperLeakCollection.COLLECTED && it != WrapperLeakCollection.NOISY_CONTROLS })
            assertEquals(WrapperLeakVerdict.NOT_EVALUATED, positive.copy(collection = state).verdict)
        assertEquals(WrapperLeakVerdict.INCONCLUSIVE, positive.copy(collection = WrapperLeakCollection.NOISY_CONTROLS).verdict)
        for (partial in listOf(positive.copy(reopens = 767), positive.copy(completedRounds = 2),
            positive.copy(error = 13), positive.copy(points = positive.points.dropLast(1)),
            positive.copy(points = positive.points.map { it.copy(median = -1) })))
            assertEquals(WrapperLeakVerdict.INCONCLUSIVE, partial.verdict)
    }
}
