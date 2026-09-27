/*
 * Copyright 2026 Duck Apps Contributor
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

package com.eltavine.duckdetector.features.settings.ui.components

import androidx.compose.animation.core.exponentialDecay
import androidx.compose.runtime.BroadcastFrameClock
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.abs

class ContributorWallMotionTest {
    @Test
    fun sequentialPointerReleasesRetainTheLastMultiTouchVelocity() {
        val velocity = Offset(1500f, -500f)
        val handoff = WallVelocityHandoff(velocity, uptimeMillis = 100L)
        assertEquals(velocity, handoff.velocityAtRelease(116L))
    }

    @Test
    fun holdingTheRemainingFingerDoesNotReuseStaleVelocity() {
        val handoff = WallVelocityHandoff(Offset(1500f, -500f), uptimeMillis = 100L)
        assertNull(handoff.velocityAtRelease(150L))
        assertNull(handoff.velocityAtRelease(90L))
    }

    @Test
    fun releaseKeepsMovingAndGraduallySlowsDown() {
        val frames = animate(Offset.Zero, Offset(1500f, 0f), Offset(5000f, 5000f))
        assertTrue(frames[10].x > frames[1].x + 100f)
        assertTrue(frames.last().x > frames[10].x)
        assertTrue(frames.zipWithNext().all { (a, b) -> b.x >= a.x })
        assertTrue(frames[5].x - frames[4].x > frames[20].x - frames[19].x)
    }

    @Test
    fun hittingOneEdgeDoesNotStopMotionAlongTheOtherAxis() {
        val frames = animate(Offset.Zero, Offset(2000f, 2000f), Offset(30f, 5000f))
        assertTrue(frames.any { it.x > 30f })
        assertTrue(frames.all { it.x < 30f + 300f * 0.18f })
        assertEquals(30f, frames.last().x, 0.01f)
        val settled = frames.indexOfLast { abs(it.x - 30f) > 0.1f }
        assertTrue(frames.last().y > frames[settled].y)
    }

    @Test
    fun releasingOverscrollReturnsInsideAllFourBoundaries() {
        for (direction in listOf(-1f, 1f)) {
            val frames = animate(Offset(70f, 90f) * direction, Offset.Zero, Offset(30f, 40f))
            assertEquals(30f * direction, frames.last().x, 0.01f)
            assertEquals(40f * direction, frames.last().y, 0.01f)
        }
    }

    @Test
    fun cancellingMotionStopsFurtherPositionUpdates() {
        val clock = BroadcastFrameClock()
        runBlocking(clock) {
            var position = Offset.Zero
            val job = launch {
                settleContributorWall(
                    Offset.Zero, Offset(2000f, 1000f), Offset(5000f, 5000f), Size(300f, 300f),
                    exponentialDecay(),
                ) { position = it }
            }
            yield()
            repeat(10) { clock.sendFrame(it * 16_000_000L); yield() }
            assertTrue(position.getDistance() > 0f)
            job.cancelAndJoin()
            val stopped = position
            repeat(30) { clock.sendFrame((it + 10) * 16_000_000L); yield() }
            assertEquals(stopped, position)
        }
    }

    private fun animate(initial: Offset, velocity: Offset, limit: Offset): List<Offset> {
        val frames = mutableListOf(initial)
        val clock = BroadcastFrameClock()
        runBlocking(clock) {
            var position = initial
            val job = launch {
                settleContributorWall(initial, velocity, limit, Size(300f, 300f), exponentialDecay()) {
                    position = it
                }
            }
            yield()
            repeat(600) {
                if (job.isActive) {
                    clock.sendFrame(it * 16_000_000L)
                    yield()
                    frames += position
                }
            }
            assertTrue("motion did not settle", job.isCompleted)
        }
        return frames
    }
}
