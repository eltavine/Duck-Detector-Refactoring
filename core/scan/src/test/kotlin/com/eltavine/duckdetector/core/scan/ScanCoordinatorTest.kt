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

package com.eltavine.duckdetector.core.scan

import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ScanCoordinatorTest {

    private val clock = FakeClock()

    @Test
    fun `session finishes the first time every detector is ready`() = runTest(UnconfinedTestDispatcher()) {
        val su = MutableStateFlow(summary("su", ready = false))
        val tee = MutableStateFlow(summary("tee", ready = false))
        clock.elapsed = 1_000
        val coordinator = ScanCoordinator(clock, backgroundScope, listOf(su, tee))

        clock.elapsed = 1_400
        su.value = summary("su", ready = true)
        assertTrue(coordinator.state.value.isLoading)
        assertNull(coordinator.state.value.timeline.durationMillis)

        clock.elapsed = 2_250
        clock.wall = 1_700_000_000_000
        tee.value = summary("tee", ready = true)

        val state = coordinator.state.value
        assertFalse(state.isLoading)
        assertEquals(2, state.readyCount)
        assertEquals(1, state.timeline.session)
        assertEquals(1_250L, state.timeline.durationMillis)
        assertEquals(1_700_000_000_000L, state.timeline.completedAtEpochMillis)
    }

    @Test
    fun `completion time is not refreshed while detectors stay ready`() = runTest(UnconfinedTestDispatcher()) {
        val su = MutableStateFlow(summary("su", ready = false))
        val coordinator = ScanCoordinator(clock, backgroundScope, listOf(su))
        clock.elapsed = 500
        su.value = summary("su", ready = true, headline = "Clean")
        val finished = coordinator.state.value.timeline

        clock.elapsed = 9_000
        su.value = summary("su", ready = true, headline = "Clean again")

        assertEquals(finished, coordinator.state.value.timeline)
        assertEquals("Clean again", coordinator.state.value.detectors.single().headline)
    }

    @Test
    fun `a detector returning to loading starts a new session`() = runTest(UnconfinedTestDispatcher()) {
        val tee = MutableStateFlow(summary("tee", ready = true))
        clock.elapsed = 100
        val coordinator = ScanCoordinator(clock, backgroundScope, listOf(tee))
        assertEquals(0L, coordinator.state.value.timeline.durationMillis)

        clock.elapsed = 5_000
        tee.value = summary("tee", ready = false)
        val restarted = coordinator.state.value.timeline
        assertEquals(2, restarted.session)
        assertEquals(5_000L, restarted.startedAtElapsedMillis)
        assertNull(restarted.finishedAtElapsedMillis)
        assertNull(restarted.completedAtEpochMillis)

        clock.elapsed = 5_900
        tee.value = summary("tee", ready = true)
        assertEquals(900L, coordinator.state.value.timeline.durationMillis)
    }

    @Test
    fun `completion callback observes each coordinator session without collecting its StateFlow`() =
        runTest(UnconfinedTestDispatcher()) {
            val tee = MutableStateFlow(summary("tee", ready = false))
            val completed = mutableListOf<Int>()
            ScanCoordinator(clock, backgroundScope, listOf(tee)) { state ->
                completed += state.timeline.session
            }
            repeat(10) {
                tee.value = summary("tee", ready = true)
                tee.value = summary("tee", ready = false)
            }
            assertEquals((1..10).toList(), completed)
        }

    @Test
    fun `timeline advance is a no-op while loading continues`() {
        val loading = ScanTimeline(session = 3, startedAtElapsedMillis = 10)

        assertEquals(loading, loading.advance(isLoading = true, clock = clock))
    }

    @Test
    fun `duration never goes negative`() {
        assertEquals(0L, ScanTimeline(1, startedAtElapsedMillis = 50, finishedAtElapsedMillis = 10).durationMillis)
    }

    @Test
    fun `no detectors means an immediately finished session`() = runTest(UnconfinedTestDispatcher()) {
        clock.elapsed = 42
        val coordinator = ScanCoordinator(clock, backgroundScope, emptyList())

        assertFalse(coordinator.state.value.isLoading)
        assertEquals(0L, coordinator.state.value.timeline.durationMillis)
    }

    private fun summary(id: String, ready: Boolean, headline: String = "Pending") = DetectorSummary(
        id = DetectorId(id),
        title = id,
        status = DetectorStatus.allClear(),
        headline = headline,
        summary = "",
        ready = ready,
    )

    private class FakeClock : ScanClock {
        var elapsed = 0L
        var wall = 0L

        override fun elapsedRealtimeMillis(): Long = elapsed

        override fun currentTimeMillis(): Long = wall
    }
}
