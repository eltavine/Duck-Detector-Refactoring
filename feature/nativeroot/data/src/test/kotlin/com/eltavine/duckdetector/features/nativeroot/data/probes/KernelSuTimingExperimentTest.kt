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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import com.eltavine.duckdetector.features.nativeroot.data.native.KernelSuTimingWindow
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreStatus
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KernelSuTimingExperimentTest {
    private class Backend : KernelSuTimingBackend {
        val calls = mutableListOf<Pair<Int, Boolean>>()
        var enabled = true
        var awake = true
        var clock = 0L
        var cores = listOf(0, 1)
        var preflightTick = 100uL
        var onSample: (Int, Boolean) -> Unit = { _, _ -> }
        var main: (Int) -> KernelSuTimingWindow = { window(it, true) }
        override fun supported() = enabled
        override fun interactive() = awake
        override fun cpus() = cores
        override fun elapsedMillis() = clock
        override fun sample(cpu: Int, preflight: Boolean): KernelSuTimingWindow {
            calls += cpu to preflight
            onSample(cpu, preflight)
            return if (preflight) KernelSuTimingWindow(KernelSuTimingCoreStatus.MEASURED, 0,
                19200000uL, true, listOf(List(10000) { preflightTick })) else main(cpu)
        }
    }

    @Test fun `preflight once and three positives on first core stop enumeration sampling`() {
        val backend = Backend()
        val result = KernelSuTimingExperiment(backend).collect { false }
        assertEquals(listOf(-1 to true, 0 to false, 0 to false, 0 to false), backend.calls)
        assertEquals(KernelSuTimingVerdict.REPEATED_PATTERN, result.verdict)
    }

    @Test fun `negative breaks a core and no positive is aggregated across cores`() {
        val backend = Backend()
        var round = 0
        backend.main = { cpu -> window(cpu, ++round % 3 != 0) }
        val result = KernelSuTimingExperiment(backend).collect { false }
        assertEquals(7, backend.calls.size)
        assertEquals(KernelSuTimingVerdict.NOT_OBSERVED, result.verdict)
    }

    @Test fun `noninteractive deadline and cancellation abort without a cached verdict`() {
        for (kind in 0..2) {
            val backend = Backend()
            var cancelled = false
            backend.onSample = { cpu, _ -> if (cpu == 0) when (kind) {
                0 -> backend.awake = false
                1 -> backend.clock = 40000
                else -> cancelled = true
            } }
            val result = KernelSuTimingExperiment(backend).collect { cancelled }
            assertEquals(listOf(KernelSuTimingCollection.NONINTERACTIVE, KernelSuTimingCollection.TIMED_OUT,
                KernelSuTimingCollection.CANCELLED)[kind], result.collection)
            assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, result.verdict)
            assertEquals(2, backend.calls.size)
        }
    }

    @Test fun `unsupported and rejected preflight never start a main round`() {
        val backend = Backend()
        backend.enabled = false
        assertEquals(KernelSuTimingCollection.UNSUPPORTED, KernelSuTimingExperiment(backend).collect { false }.collection)
        assertEquals(0, backend.calls.size)
        backend.enabled = true
        backend.preflightTick = 136uL
        assertEquals(KernelSuTimingCollection.PREFLIGHT_REJECTED, KernelSuTimingExperiment(backend).collect { false }.collection)
        assertEquals(listOf(-1 to true), backend.calls)
    }

    @Test fun `failed binding is partial and failed cleanup stops the run`() {
        val backend = Backend()
        backend.main = { window(it, false).copy(status = KernelSuTimingCoreStatus.AFFINITY_FAILED,
            frequency = 0uL, actualCpu = null, vectors = emptyList()) }
        val bindingFailure = KernelSuTimingExperiment(backend).collect { false }
        assertEquals(KernelSuTimingCollection.PARTIAL, bindingFailure.collection)
        assertTrue(bindingFailure.attempts.all { it.status == KernelSuTimingCoreStatus.AFFINITY_FAILED })
        backend.calls.clear()
        backend.main = { window(it, true).copy(cleanup = false) }
        val result = KernelSuTimingExperiment(backend).collect { false }
        assertFalse(result.cleanupCompleted)
        assertEquals(2, backend.calls.size)
        assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, result.verdict)
    }

    companion object {
        private fun window(cpu: Int, positive: Boolean) = KernelSuTimingWindow(
            KernelSuTimingCoreStatus.MEASURED, cpu, 19200000uL, true,
            listOf(10uL, if (positive) 20uL else 10uL, 10uL, 10uL, 10uL, 10uL)
                .map { ticks -> List(10000) { ticks } },
        )
    }
}
