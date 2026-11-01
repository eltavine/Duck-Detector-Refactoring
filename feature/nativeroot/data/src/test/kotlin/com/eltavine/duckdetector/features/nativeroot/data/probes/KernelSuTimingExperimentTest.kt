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
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCpuSnapshot
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingPreflightStatus
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingSyscallSummary
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
        var snapshot = KernelSuTimingCpuSnapshot(listOf(0, 1), listOf(0, 1), listOf(0, 1))
        var onSample: (Int, Boolean) -> Unit = { _, _ -> }
        var preflight: (Int) -> KernelSuTimingWindow = { cpu -> window(cpu, true, true) }
        var main: (Int) -> KernelSuTimingWindow = { cpu -> window(cpu, true) }
        override fun supported() = enabled
        override fun interactive() = awake
        override fun cpuSnapshot() = snapshot
        override fun elapsedMillis() = clock
        override fun sample(cpu: Int, preflight: Boolean): KernelSuTimingWindow {
            calls += cpu to preflight
            onSample(cpu, preflight)
            return if (preflight) this.preflight(cpu) else main(cpu)
        }
    }

    @Test fun `three positives on one CPU confirm with its own preflight`() {
        val backend = Backend()
        val result = KernelSuTimingExperiment(backend).collect { false }
        assertEquals(listOf(0 to true, 0 to false, 0 to false, 0 to false), backend.calls)
        assertEquals(KernelSuTimingVerdict.REPEATED_PATTERN, result.verdict)
    }

    @Test fun `preflight rejection on one CPU does not veto another CPU`() {
        val backend = Backend()
        backend.preflight = { cpu -> window(cpu, true, true).let { if (cpu == 0)
            it.copy(vectors = listOf(List(10000) { index -> (index % 751).toULong() })) else it } }
        val result = KernelSuTimingExperiment(backend).collect { false }
        assertEquals(listOf(0 to true, 1 to true, 1 to false, 1 to false, 1 to false), backend.calls)
        assertEquals(KernelSuTimingCoreStatus.PREFLIGHT_REJECTED, result.attempts[0].status)
        assertEquals(KernelSuTimingVerdict.REPEATED_PATTERN, result.verdict)
    }

    @Test fun `tick gate rejects only the affected CPU regardless of counter frequency`() {
        for (frequency in listOf(19200000uL, 100000000uL)) {
            for (positive in listOf(false, true)) {
                val backend = Backend()
                backend.preflight = { cpu -> window(cpu, true, true).copy(frequency = frequency,
                    vectors = listOf(List(10000) { if (cpu == 0) 136uL else 135uL })) }
                backend.main = { window(it, positive).copy(frequency = frequency) }
                val result = KernelSuTimingExperiment(backend).collect { false }
                assertEquals(listOf(0 to true, 1 to true) + List(if (positive) 3 else 1) { 1 to false },
                    backend.calls)
                assertEquals(KernelSuTimingCoreStatus.PREFLIGHT_REJECTED, result.attempts[0].status)
                assertEquals(KernelSuTimingPreflightStatus.EXCESSIVE_MINIMUM, result.attempts[0].preflight.status)
                assertEquals(136uL, result.attempts[0].preflight.minimumTicks)
                assertEquals(KernelSuTimingPreflightStatus.ACCEPTED, result.attempts[1].preflight.status)
                assertEquals(if (positive) KernelSuTimingVerdict.REPEATED_PATTERN else KernelSuTimingVerdict.INCONCLUSIVE,
                    result.verdict)
            }
        }
    }

    @Test fun `all CPUs above the tick gate remain inconclusive without main sampling`() {
        val backend = Backend()
        backend.preflight = { window(it, true, true).copy(vectors = listOf(List(10000) { 136uL })) }
        val result = KernelSuTimingExperiment(backend).collect { false }
        assertEquals(listOf(0 to true, 1 to true), backend.calls)
        assertTrue(result.attempts.all { it.preflight.status == KernelSuTimingPreflightStatus.EXCESSIVE_MINIMUM })
        assertTrue(result.sampledCpus.isEmpty())
        assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, result.verdict)
    }

    @Test fun `negative endings are per CPU and no positive is accumulated across CPUs`() {
        val backend = Backend()
        var round = 0
        backend.main = { cpu -> window(cpu, ++round % 3 != 0) }
        val result = KernelSuTimingExperiment(backend).collect { false }
        assertEquals(8, backend.calls.size)
        assertEquals(KernelSuTimingVerdict.NOT_OBSERVED, result.verdict)
        assertEquals(listOf(0, 1), result.sampledCpus)
    }

    @Test fun `offline and disallowed present CPUs remain incomplete despite eligible negatives`() {
        for (offline in listOf(false, true)) {
            val backend = Backend()
            backend.snapshot = backend.snapshot.copy(online = if (offline) listOf(0) else listOf(0, 1),
                allowed = if (offline) listOf(0, 1) else listOf(0))
            backend.main = { window(it, false).copy(allowedCpus = backend.snapshot.allowed.orEmpty()) }
            backend.preflight = { window(it, true, true).copy(allowedCpus = backend.snapshot.allowed.orEmpty()) }
            val result = KernelSuTimingExperiment(backend).collect { false }
            assertEquals(listOf(0 to true, 0 to false), backend.calls)
            assertEquals(listOf(0, 1), result.initialCpus.present)
            assertTrue(result.attempts.single().completed)
            assertEquals(KernelSuTimingCollection.PARTIAL, result.collection)
            assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, result.verdict)
        }
    }

    @Test fun `hotplug cpuset changes and mismatched worker affinity invalidate the affected window`() {
        for (kind in 0..2) {
            val backend = Backend()
            if (kind < 2) backend.onSample = { _, _ -> backend.snapshot = if (kind == 0)
                backend.snapshot.copy(online = listOf(0)) else backend.snapshot.copy(allowed = listOf(0)) }
            else backend.preflight = { window(it, true, true).copy(allowedCpus = listOf(0)) }
            val result = KernelSuTimingExperiment(backend).collect { false }
            assertEquals(KernelSuTimingCoreStatus.ELIGIBILITY_CHANGED, result.attempts.first().status)
            assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, result.verdict)
        }
    }

    @Test fun `sparse histogram support cannot complete a negative CPU ending`() {
        val backend = Backend()
        backend.main = { cpu -> window(cpu, false).copy(vectors = List(6) { List(10000) { it.toULong() } }) }
        val result = KernelSuTimingExperiment(backend).collect { false }
        assertTrue(result.attempts.all { it.status == KernelSuTimingCoreStatus.INSUFFICIENT_SUPPORT })
        assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, result.verdict)
    }

    @Test fun `unexpected syscall outcomes or any retries are reported as contaminated`() {
        for (summary in listOf(KernelSuTimingSyscallSummary(mapOf(-1L to 10000)),
            KernelSuTimingSyscallSummary(mapOf(0L to 5000, -22L to 5000)),
            KernelSuTimingSyscallSummary(mapOf(-22L to 10000), retriedSamples = 1, totalRetries = 1, maximumRetries = 1))) {
            val backend = Backend()
            backend.main = { window(it, false).copy(outcomes = List(6) { summary }) }
            val result = KernelSuTimingExperiment(backend).collect { false }
            assertTrue(result.attempts.all { it.status == KernelSuTimingCoreStatus.OUTCOME_CONTAMINATED })
            assertEquals(summary, result.attempts.first().windows.last().outcomes.first())
            assertEquals(listOf(0, 1), result.sampledCpus)
            assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, result.verdict)
        }
    }

    @Test fun `noninteractive deadline cancellation and failed cleanup stop further sampling`() {
        for (kind in 0..3) {
            val backend = Backend()
            var cancelled = false
            backend.onSample = { _, _ -> when (kind) {
                0 -> backend.awake = false
                1 -> backend.clock = 40000
                2 -> cancelled = true
            } }
            if (kind == 3) backend.preflight = { window(it, true, true).copy(cleanup = false) }
            val result = KernelSuTimingExperiment(backend).collect { cancelled }
            assertEquals(listOf(KernelSuTimingCollection.NONINTERACTIVE, KernelSuTimingCollection.TIMED_OUT,
                KernelSuTimingCollection.CANCELLED, KernelSuTimingCollection.PARTIAL)[kind], result.collection)
            assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, result.verdict)
            assertEquals(1, backend.calls.size)
        }
    }

    @Test fun `unsupported or unreadable inventory starts no syscall windows`() {
        val backend = Backend()
        backend.enabled = false
        assertEquals(KernelSuTimingCollection.UNSUPPORTED, KernelSuTimingExperiment(backend).collect { false }.collection)
        backend.enabled = true
        backend.snapshot = backend.snapshot.copy(online = null, detail = "online: permission denied")
        assertEquals(KernelSuTimingCollection.UNAVAILABLE, KernelSuTimingExperiment(backend).collect { false }.collection)
        assertTrue(backend.calls.isEmpty())
    }

    @Test fun `failed binding remains partial but allows later CPUs`() {
        val backend = Backend()
        backend.preflight = { cpu -> window(cpu, true, true).let { if (cpu == 0)
            it.copy(status = KernelSuTimingCoreStatus.AFFINITY_FAILED, vectors = emptyList(), outcomes = emptyList()) else it } }
        val result = KernelSuTimingExperiment(backend).collect { false }
        assertEquals(KernelSuTimingCoreStatus.AFFINITY_FAILED, result.attempts.first().status)
        assertEquals(KernelSuTimingVerdict.REPEATED_PATTERN, result.verdict)
        assertFalse(result.attempts.first().completed)
    }

    @Test fun `sparse CPU IDs can complete while present CPUs beyond budget remain partial`() {
        for (present in listOf(listOf(2, 7), (0..16).toList())) {
            val backend = Backend()
            backend.snapshot = KernelSuTimingCpuSnapshot(present, present, present)
            backend.preflight = { window(it, true, true).copy(allowedCpus = present) }
            backend.main = { window(it, false).copy(allowedCpus = present) }
            val result = KernelSuTimingExperiment(backend).collect { false }
            assertEquals(present.take(16), result.sampledCpus)
            assertEquals(if (present.size > 16) KernelSuTimingVerdict.INCONCLUSIVE else KernelSuTimingVerdict.NOT_OBSERVED,
                result.verdict)
        }
    }

    @Test fun `a frequency change after preflight invalidates that CPU without a negative ending`() {
        val backend = Backend()
        backend.main = { window(it, false).copy(frequency = 100000000uL) }
        val result = KernelSuTimingExperiment(backend).collect { false }
        assertTrue(result.attempts.all { it.status == KernelSuTimingCoreStatus.TIMER_UNAVAILABLE })
        assertEquals(KernelSuTimingVerdict.INCONCLUSIVE, result.verdict)
    }

    companion object {
        private fun window(cpu: Int, positive: Boolean, preflight: Boolean = false) = KernelSuTimingWindow(
            KernelSuTimingCoreStatus.MEASURED, cpu, 19200000uL, true,
            (if (preflight) listOf(100uL) else listOf(10uL, if (positive) 20uL else 10uL, 10uL, 10uL, 10uL, 10uL))
                .map { ticks -> List(10000) { ticks } }, listOf(0, 1),
            List(if (preflight) 1 else 6) { KernelSuTimingSyscallSummary(mapOf(-22L to 10000)) },
        )
    }
}
