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
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteProfile
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProcMountViewDivergenceProbeTest {

    private val probe = ProcMountViewDivergenceProbe()

    @Test
    fun `divergent mount views map to warning finding`() {
        val result = probe.evaluate(
            isolatedSnapshot = VirtualizationRemoteSnapshot(
                available = true,
                profile = VirtualizationRemoteProfile.ISOLATED,
                procMountViewAvailable = true,
                procMountViewCount = 2,
                procMountViewExpected = 1,
                procMountViewPidCount = 40,
                procMountViewDivergent = true,
            ),
        )

        assertTrue(result.available)
        assertTrue(result.isolatedProcessAvailable)
        assertEquals(1, result.signalCount)
        assertEquals("Hidden mount view divergence", result.findings.single().label)
        assertEquals(NativeRootFindingSeverity.WARNING, result.findings.single().severity)
        assertTrue(result.findings.single().detail.contains("2"))
    }

    @Test
    fun `direct root token maps to danger finding`() {
        val result = probe.evaluate(
            isolatedSnapshot = VirtualizationRemoteSnapshot(
                available = true,
                profile = VirtualizationRemoteProfile.ISOLATED,
                procMountViewAvailable = true,
                procMountViewCount = 1,
                procMountViewExpected = 1,
                procMountViewPidCount = 40,
                procMountViewDivergent = false,
                procMountViewTokenHit = true,
                procMountViewTokenDetail = "/magisk /system overlay rw,seclabel",
            ),
        )

        assertTrue(result.available)
        assertEquals(1, result.signalCount)
        assertEquals("Root mount token in process view", result.findings.single().label)
        assertEquals(NativeRootFindingSeverity.DANGER, result.findings.single().severity)
        assertTrue(result.findings.single().detail.contains("/magisk"))
    }

    @Test
    fun `clean views produce no findings`() {
        val result = probe.evaluate(
            isolatedSnapshot = VirtualizationRemoteSnapshot(
                available = true,
                profile = VirtualizationRemoteProfile.ISOLATED,
                procMountViewAvailable = true,
                procMountViewCount = 1,
                procMountViewExpected = 1,
                procMountViewPidCount = 40,
                procMountViewDivergent = false,
                procMountViewTokenHit = false,
            ),
        )

        assertTrue(result.available)
        assertTrue(result.isolatedProcessAvailable)
        assertEquals(0, result.signalCount)
        assertTrue(result.findings.isEmpty())
        assertFalse(result.divergent)
    }

    @Test
    fun `missing mount view scan stays unavailable`() {
        val result = probe.evaluate(
            isolatedSnapshot = VirtualizationRemoteSnapshot(
                available = true,
                profile = VirtualizationRemoteProfile.ISOLATED,
                procMountViewAvailable = false,
            ),
        )

        assertTrue(result.available)
        assertFalse(result.isolatedProcessAvailable)
        assertEquals(0, result.signalCount)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `unavailable isolated process stays unavailable`() {
        val result = probe.evaluate(
            isolatedSnapshot = VirtualizationRemoteSnapshot(
                available = false,
                errorDetail = "Isolated helper timed out.",
            ),
        )

        assertFalse(result.available)
        assertFalse(result.isolatedProcessAvailable)
        assertEquals(0, result.signalCount)
    }
}
