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

package com.eltavine.duckdetector.features.nativeroot.data.repository

import com.eltavine.duckdetector.features.nativeroot.data.native.NativeRootNativeSnapshot
import com.eltavine.duckdetector.features.nativeroot.data.native.SusfsProbeOutcome
import com.eltavine.duckdetector.features.nativeroot.data.probes.KernelSuThroneHuntProbe
import com.eltavine.duckdetector.features.nativeroot.data.probes.KernelSuThroneHuntRoundResult
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeRootMethodRowsTest {

    @Test
    fun `directory events do not enter runtime or signal summaries`() {
        val result = KernelSuThroneHuntProbe().run(
            KernelSuThroneHuntRoundResult(
                available = true,
                stimulusApplied = true,
                directoryOpenCount = 3,
                directoryAccessCount = 3,
                rawEventCount = 42,
                detail = "round detail",
            )
        )
        val snapshot = NativeRootNativeSnapshot(available = true)
        val row = methodRow(snapshot, "ksuThroneHunt", result)

        assertEquals("6 unattributed event(s)", row.summary)
        assertEquals(NativeRootMethodOutcome.SUPPORT, row.outcome)
        assertTrue(row.detail.contains("cannot identify KernelSU"))
        assertTrue(row.detail.contains("raw=42"))
        for (label in listOf("runtimeArtifacts", "signalSummary")) {
            val summary = methodRow(snapshot, label, result)
            assertEquals("Clean", summary.summary)
            assertEquals(NativeRootMethodOutcome.CLEAN, summary.outcome)
        }
    }

    @Test
    fun `zero directory events remain support instead of clean`() {
        val result = KernelSuThroneHuntProbe().run(
            KernelSuThroneHuntRoundResult(available = true, stimulusApplied = true, detail = "ready")
        )
        val row = methodRow(NativeRootNativeSnapshot(available = true), "ksuThroneHunt", result)

        assertEquals("No directory events", row.summary)
        assertEquals(NativeRootMethodOutcome.SUPPORT, row.outcome)
        assertTrue(row.detail.contains("zero events cannot exclude"))
    }

    @Test
    fun `failed stimulus takes precedence over preserved directory counts`() {
        val result = KernelSuThroneHuntProbe().run(
            KernelSuThroneHuntRoundResult(
                available = false,
                stimulusApplied = false,
                failureStage = "STIMULUS_FAILED",
                directoryOpenCount = 3,
                directoryAccessCount = 3,
                detail = "partial collection",
            )
        )
        val row = methodRow(NativeRootNativeSnapshot(available = true), "ksuThroneHunt", result)

        assertEquals("STIMULUS_FAILED", row.summary)
        assertEquals(NativeRootMethodOutcome.SUPPORT, row.outcome)
        assertTrue(row.detail.contains("open=3 access=3"))
    }

    @Test
    fun `latency probe that never measured is unavailable even when the snapshot is available`() {
        val row = methodRow(
            NativeRootNativeSnapshot(
                available = true,
                kernelPatchSideChannelAvailable = false,
                kernelPatchSideChannelDetail = "Not run: KernelPatch's supercall is syscall 45 of the arm64 table.",
            ),
            LATENCY_ROW,
        )

        assertEquals("Unavailable", row.summary)
        assertEquals(NativeRootMethodOutcome.SUPPORT, row.outcome)
    }

    @Test
    fun `a measured ratio below threshold remains supporting evidence`() {
        val row = methodRow(NativeRootNativeSnapshot(available = true, kernelPatchSideChannelAvailable = true), LATENCY_ROW)

        assertEquals("Ratio below threshold", row.summary)
        assertEquals(NativeRootMethodOutcome.SUPPORT, row.outcome)
    }

    @Test
    fun `an elevated ratio is supporting evidence without root attribution`() {
        val row = methodRow(
            NativeRootNativeSnapshot(
                available = true,
                kernelPatchSideChannel = true,
                kernelPatchSideChannelAvailable = true,
            ),
            LATENCY_ROW,
        )
        assertEquals("Elevated ratio", row.summary)
        assertEquals(NativeRootMethodOutcome.SUPPORT, row.outcome)
    }

    @Test
    fun `an unavailable ratio takes precedence over an elevated flag`() {
        val row = methodRow(
            NativeRootNativeSnapshot(kernelPatchSideChannel = true), LATENCY_ROW,
        )
        assertEquals("Unavailable", row.summary)
        assertEquals(NativeRootMethodOutcome.SUPPORT, row.outcome)
    }

    @Test
    fun `susfs probe reads its outcome instead of the snapshot availability`() {
        fun row(outcome: SusfsProbeOutcome) =
            methodRow(NativeRootNativeSnapshot(available = true, susfsProbeOutcome = outcome), SUSFS_ROW)

        assertEquals(NativeRootMethodOutcome.SUPPORT, row(SusfsProbeOutcome.NOT_OBSERVED).outcome)
        assertEquals("Normal", row(SusfsProbeOutcome.DENIED).summary)
        assertEquals(NativeRootMethodOutcome.DETECTED, row(SusfsProbeOutcome.KILLED).outcome)
        assertEquals("UID changed", row(SusfsProbeOutcome.CHANGED_UID).summary)
        assertEquals(NativeRootMethodOutcome.DETECTED, row(SusfsProbeOutcome.CHANGED_UID).outcome)
    }

    private companion object {
        const val LATENCY_ROW = "__NR_supercall probe"
        const val SUSFS_ROW = "susfsSideChannel"
    }
}
