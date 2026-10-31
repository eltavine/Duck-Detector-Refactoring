package com.eltavine.duckdetector.features.nativeroot.presentation

import com.eltavine.duckdetector.features.nativeroot.domain.*
import org.junit.Assert.*
import org.junit.Test
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind

class KernelSuWrapperLeakPresentationTest {
    private fun positive(): KernelSuWrapperLeakObservation {
        val values = listOf(10000L,10000,10000,10256,10256,10256,10256,10512,10512,10512,10512,10768,10768,10768)
        return KernelSuWrapperLeakObservation(WrapperLeakCollection.COLLECTED, 0, 3, 768,
            values.map { WrapperFileNrPoint(it, 0) })
    }
    @Test fun `warning appears in method headline summary and exported report without root attribution`() {
        val report = NativeRootReport.loading().copy(stage = NativeRootStage.READY, nativeAvailable = true,
            wrapperLeak = positive())
        val model = NativeRootCardModelMapper().map(report)
        assertEquals(NativeRootMethodOutcome.WARNING, wrapperLeakMethod(positive()).outcome)
        assertTrue(model.verdict.contains("file-object growth"))
        assertTrue(model.summary.contains("does not identify KSU or root"))
        assertTrue(model.methodRows.any { it.label == "ksuWrapperReferenceLeak" })
        assertFalse(report.rootDetected)
        assertFalse(report.kernelSuDetected)
        assertTrue(model.toDetectorReport().toString().contains("ksuWrapperReferenceLeak"))
    }
    @Test fun `missing candidate restrictions and errors are support only`() {
        for (state in listOf(WrapperLeakCollection.NO_CANDIDATE, WrapperLeakCollection.PERMISSION_LIMITED,
            WrapperLeakCollection.CLEANUP_FAILED, WrapperLeakCollection.TIMED_OUT)) {
            val row = wrapperLeakMethod(positive().copy(collection = state))
            assertEquals(NativeRootMethodOutcome.SUPPORT, row.outcome)
            assertFalse(row.summary.contains("Clean"))
            assertFalse(row.summary.contains("Repeated"))
        }
    }
    @Test fun `applicable failures reduce coverage in both card and export`() {
        val covered = NativeRootReport.loading().copy(stage = NativeRootStage.READY,
            nativeAvailable = true, cgroupAvailable = true, ksuSupercallAttempted = true,
            isolatedMountProbeAvailable = true, ksuThroneHuntAvailable = true, ksuThroneHuntStimulusApplied = true)
        assertFalse(covered.hasReducedCoverage())
        for (state in WrapperLeakCollection.entries.filter { it !in setOf(
            WrapperLeakCollection.COLLECTED, WrapperLeakCollection.NOT_REQUESTED, WrapperLeakCollection.NO_CANDIDATE) }) {
            val report = covered.copy(wrapperLeak = KernelSuWrapperLeakObservation(collection = state))
            val model = NativeRootCardModelMapper().map(report)
            assertTrue(report.hasReducedCoverage())
            assertEquals(DetectorStatus.info(InfoKind.SUPPORT), model.status)
            assertEquals(model.status.severity, model.toDetectorReport().severity)
            assertFalse(report.rootDetected)
            assertFalse(report.kernelSuDetected)
        }
    }
    @Test fun `not requested is explicitly unevaluated and scanner budget is disclosed`() {
        assertEquals("Not evaluated", wrapperLeakMethod(KernelSuWrapperLeakObservation()).summary)
        assertTrue(wrapperLeakMethod(positive()).detail.contains("new scanner has a new budget"))
    }
}
