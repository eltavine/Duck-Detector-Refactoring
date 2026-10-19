package com.eltavine.duckdetector.features.nativeroot.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingAnalysis
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreAttempt
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreStatus
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingDistance
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingObservation
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingPreflight
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingSimilarity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootStage
import com.eltavine.duckdetector.features.nativeroot.domain.hasReducedCoverage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KernelSuTimingPresentationTest {
    @Test fun `timing alone is warning only and retains metrics in export`() {
        val round = KernelSuTimingAnalysis(KernelSuTimingDistance(10000, 0, 10000, 10000),
            KernelSuTimingSimilarity(1.0, 0.0, 1.0, 1.0, 1.0, 10.0, 20.0))
        val observation = KernelSuTimingObservation(KernelSuTimingCollection.COLLECTED,
            KernelSuTimingPreflight.fromFrequencies(listOf(100uL, 10000uL)), listOf(0),
            listOf(KernelSuTimingCoreAttempt(0, 0, KernelSuTimingCoreStatus.MEASURED, List(3) { round })),
            19200000uL, true)
        val report = NativeRootReport.loading().copy(stage = NativeRootStage.READY, kernelSuTiming = observation)
        val model = NativeRootCardModelMapper().map(report)
        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals("Repeated prctl timing pattern", model.verdict)
        assertEquals(DetectorStatus.warning(), model.impactItems.first().status)
        assertFalse(report.rootDetected)
        assertFalse(report.kernelSuDetected)
        assertTrue(report.detectedFamilies.isEmpty())
        assertTrue(model.toDetectorReport().toString().contains("frequency", ignoreCase = true))
        assertTrue(model.methodRows.last().detail.orEmpty().contains("actual=0"))
    }

    @Test fun `failure states are explicit and reduce coverage without clean timing row`() {
        for (state in listOf(KernelSuTimingCollection.NONINTERACTIVE, KernelSuTimingCollection.TIMED_OUT,
            KernelSuTimingCollection.WORKER_DIED, KernelSuTimingCollection.PROTOCOL_ERROR)) {
            val observation = KernelSuTimingObservation(collection = state)
            assertTrue(NativeRootReport.loading().copy(kernelSuTiming = observation).hasReducedCoverage())
            assertFalse(kernelSuTimingRow(observation).value.contains("not observed"))
            assertTrue(kernelSuTimingRow(observation).detail.orEmpty().contains("cleanup=false"))
        }
    }
}
