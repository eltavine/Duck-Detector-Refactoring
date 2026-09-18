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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
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
    fun `directory traversal yields a danger finding`() {
        val result = KernelSuThroneHuntProbe().run(readyRound)

        assertTrue(result.available)
        assertEquals(2, result.hitCount)
        val finding = result.findings.single()
        assertEquals("KernelSU throne hunt", finding.label)
        assertEquals("open=1 access=1", finding.value)
        assertEquals(NativeRootGroup.PACKAGE, finding.group)
        assertEquals(NativeRootFindingSeverity.DANGER, finding.severity)
    }

    @Test
    fun `clean round emits no finding so runtime counting stays honest`() {
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
