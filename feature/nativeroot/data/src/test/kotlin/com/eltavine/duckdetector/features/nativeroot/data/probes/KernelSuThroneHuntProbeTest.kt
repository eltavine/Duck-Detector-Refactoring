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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KernelSuThroneHuntProbeTest {

    private val readyRound = KernelSuThroneHuntRoundResult(
        available = true,
        stimulusApplied = true,
        packageDirectory = "/data/app/~~abc==/com.eltavine.duckdetector-def==",
        watchDescriptor = 12,
        directoryOpenCount = 1,
        directoryAccessCount = 1,
        detail = "watchInstalled=true",
    )

    @Test
    fun `reported directory events remain diagnostic without a root finding`() {
        val result = KernelSuThroneHuntProbe().run(
            readyRound.copy(directoryOpenCount = 3, directoryAccessCount = 3, rawEventCount = 42)
        )

        assertTrue(result.available)
        assertEquals(6, result.hitCount)
        assertEquals(42, result.rawEventCount)
        assertEquals(12, result.watchDescriptor)
        assertTrue(result.detail.contains("directoryOpen=3"))
        assertTrue(result.detail.contains("directoryAccess=3"))
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `zero event round emits no root finding`() {
        val result = KernelSuThroneHuntProbe().run(
            readyRound.copy(directoryOpenCount = 0, directoryAccessCount = 0)
        )

        assertTrue(result.available)
        assertEquals(0, result.hitCount)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `unavailable round reports no coverage and no hit`() {
        val result = KernelSuThroneHuntProbe().run(
            KernelSuThroneHuntRoundResult(
                available = false,
                stimulusApplied = false,
                detail = "The app_zygote package directory watch was not installed.",
            )
        )

        assertFalse(result.available)
        assertFalse(result.watchInstalled)
        assertEquals(0, result.hitCount)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `unavailable round preserves diagnostic counters for later review`() {
        val result = KernelSuThroneHuntProbe().run(
            KernelSuThroneHuntRoundResult(
                available = false,
                failureStage = "STIMULUS_FAILED",
                stimulusApplied = false,
                packageDirectory = "/data/app/package",
                watchDescriptor = 12,
                directoryOpenCount = 3,
                directoryAccessCount = 2,
                rawEventCount = 5,
                invalidEventCount = 1,
                baselineHitCount = 2,
                stimulusDetail = "setMimeGroup failed: binder unavailable",
                detail = "round detail",
            )
        )

        assertEquals("STIMULUS_FAILED", result.failureStage)
        assertEquals(5, result.rawEventCount)
        assertEquals(1, result.invalidEventCount)
        assertEquals(2, result.baselineHitCount)
        assertEquals(12, result.watchDescriptor)
        assertEquals(5, result.hitCount)
        assertTrue(result.findings.isEmpty())
        assertTrue(result.stimulusDetail.contains("binder unavailable"))
    }

    @Test
    fun `watch denial is reported without a hit`() {
        val result = KernelSuThroneHuntProbe().run(
            KernelSuThroneHuntRoundResult(
                available = true,
                stimulusApplied = true,
                watchDenied = true,
                detail = "inotify_add_watch denied",
            )
        )

        assertTrue(result.available)
        assertTrue(result.watchDenied)
        assertTrue(result.findings.isEmpty())
    }
}
