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

package com.eltavine.duckdetector.features.nativeroot.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingClassifier
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCpuSnapshot
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingSyscallSummary
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingWindowEvidence
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreAttempt
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreStatus
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingObservation
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingPreflight
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootStage
import com.eltavine.duckdetector.features.nativeroot.domain.hasReducedCoverage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KernelSuTimingPresentationTest {
    @Test fun `timing alone is warning only and retains metrics in export`() {
        val cpus = KernelSuTimingCpuSnapshot(listOf(0), listOf(0), listOf(0))
        val round = KernelSuTimingClassifier.summarize(listOf(10uL, 20uL, 10uL, 10uL, 10uL, 10uL)
            .map { tick -> List(10000) { tick } })
        val windows = List(4) { index -> KernelSuTimingWindowEvidence(cpus, cpus, listOf(0),
            List(if (index == 0) 1 else 6) { KernelSuTimingSyscallSummary(mapOf(-22L to 10000)) }, 19200000uL) }
        val observation = KernelSuTimingObservation(collection = KernelSuTimingCollection.COLLECTED,
            initialCpus = cpus, finalCpus = cpus, cleanupCompleted = true,
            attempts = listOf(KernelSuTimingCoreAttempt(0, 0, KernelSuTimingCoreStatus.MEASURED, List(3) { round },
                KernelSuTimingPreflight.fromFrequencies(listOf(100uL, 10000uL)), windows)))
        val report = NativeRootReport.loading().copy(stage = NativeRootStage.READY, kernelSuTiming = observation)
        val model = NativeRootCardModelMapper().map(report)
        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals("Repeated prctl timing pattern", model.verdict)
        assertEquals(DetectorStatus.warning(), model.impactItems.first().status)
        assertFalse(report.rootDetected)
        assertFalse(report.kernelSuDetected)
        assertTrue(report.detectedFamilies.isEmpty())
        assertTrue(model.toDetectorReport().toString().contains("frequency", ignoreCase = true))
        val detail = model.methodRows.last().detail.orEmpty()
        assertTrue(detail.contains("actual=0"))
        assertTrue(detail.contains("syscallOutcomes="))
        assertTrue(detail.contains("validity=VALID"))
        assertTrue(detail.contains("firstMass=10000"))
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
    @Test fun `CPU exclusions and unknown states remain visible with all present scope`() {
        val snapshot = KernelSuTimingCpuSnapshot(listOf(0, 2, 7), listOf(0, 2), listOf(0, 7))
        val row = kernelSuTimingRow(KernelSuTimingObservation(collection = KernelSuTimingCollection.PARTIAL,
            initialCpus = snapshot, finalCpus = snapshot, cleanupCompleted = true))
        val detail = row.detail.orEmpty()
        assertTrue(detail.contains("coverageScope=all present CPUs"))
        assertTrue(detail.contains("cpu=2; exclusions=[outside worker affinity/cpuset snapshot"))
        assertTrue(detail.contains("cpu=7; exclusions=[offline"))
        assertTrue(detail.contains("sampledCpus=[]"))
        assertFalse(row.value.contains("not observed"))
    }

}
