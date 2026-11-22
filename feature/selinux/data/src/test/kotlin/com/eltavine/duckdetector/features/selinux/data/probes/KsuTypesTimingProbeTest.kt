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

package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import com.eltavine.duckdetector.features.selinux.domain.toDetectorStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class KsuTypesTimingProbeTest {
    @Test
    fun `strictly exceeding three times the other counts marks danger for ksu`() {
        val samples = countPayload(1_125).toMutableList()
        samples[10] += 1L
        val timing = KsuTypesTimingProbe.interpret(samples)
        val report = SelinuxReport.loading().copy(
            stage = SelinuxStage.READY,
            mode = SelinuxMode.ENFORCING,
            methods = listOf(timing),
        )

        assertEquals("ksu_types timing with invalid types", timing.method)
        assertEquals(DetectionSeverity.DANGER, report.toDetectorStatus().severity)
        assertEquals(DetectionSeverity.DANGER, report.copy(mode = SelinuxMode.UNKNOWN).toDetectorStatus().severity)
        assertEquals(DetectionSeverity.DANGER, report.copy(mode = SelinuxMode.PERMISSIVE).toDetectorStatus().severity)
    }

    @Test
    fun `trimmed mean drops isolated extremes but retains repeated differences`() {
        val samples = batches(0, 0)
        samples[0] = 100_000_000
        samples[9] = -100_000_000
        assertNull(KsuTypesTimingProbe.interpret(samples).isSecure)

        samples[1] = 3_500_000
        samples[2] = 3_500_000
        val measured = KsuTypesTimingProbe.interpret(samples)
        assertTrue(measured.details.orEmpty().contains("Trimmed per-pair mean: ksu 1953 ns."))
        assertNull(measured.isSecure)
    }

    @Test
    fun `missing or invalid direction counts stay unavailable`() {
        assertNull(KsuTypesTimingProbe.interpret(batches(511, -511)).isSecure)
        assertNull(KsuTypesTimingProbe.interpret(countPayload(1_401)).isSecure)
        assertNull(KsuTypesTimingProbe.interpret(null).isSecure)
        assertNull(KsuTypesTimingProbe.interpret(listOf(1_000_000)).isSecure)
    }

    @Test
    fun `reports both median and mean per pair alongside the existing batch verdict`() {
        val samples = batches(512_000, -1_024_000) + listOf(900L, -1_800L)
        val timing = KsuTypesTimingProbe.interpret(samples)

        assertTrue(timing.details.orEmpty().contains("ksu per pair: median 900 ns, mean 1000 ns"))
        assertFalse(timing.details.orEmpty().contains("ksu_file"))
        assertNull(timing.isSecure)
    }

    @Test
    fun `reports nonzero differences and their directions for every batch`() {
        val counts = MutableList(18) { 0L }
        counts[0] = 12
        counts[1] = 13
        counts[16] = 32
        counts[17] = 1
        val totals = MutableList(9) { 0L }.apply {
            this[0] = -3_000L
            this[8] = 4_500L
        }
        val samples = totals + 0L + counts + 1_500L
        val details = KsuTypesTimingProbe.interpret(samples).details.orEmpty()

        assertTrue(details.contains("ksu differences by batch:\nBatch 1: 25/1500 differ (A>B 12, A<B 13, A=B 1475), mean -2 ns"))
        assertTrue(details.contains(
            "Batch 9: 33/1500 differ (A>B 32, A<B 1, A=B 1467), mean 3 ns",
        ))
    }

    @Test
    fun `exactly three times is clear and equals are included in the comparison`() {
        val timing = KsuTypesTimingProbe.interpret(countPayload(1_125))
        assertEquals("A>B: ksu 10125/13500", timing.status)
        assertTrue(timing.details.orEmpty().contains("ksu totals: A>B 10125, A<B 900, A=B 2475"))
        assertEquals(true, timing.isSecure)
    }

    @Test
    fun `a single batch exceeding the ratio stays clear when the total is below it`() {
        val samples = countPayload(1_080).toMutableList()
        samples[10] = 1_400L
        assertEquals(true, KsuTypesTimingProbe.interpret(samples).isSecure)
    }

    @Test
    fun `removes only one maximum and one minimum batch mean even when tied`() {
        val domainTotals = listOf(-100, -100, 2, 2, 2, 2, 2, 200, 200).map { it * 1_500L }
        val payload = domainTotals + 0L + List(18) { 0L } + 1_500L

        val timing = KsuTypesTimingProbe.interpret(payload)
        assertTrue(timing.details.orEmpty().contains("Trimmed per-pair mean: ksu 15 ns."))
        assertEquals(true, timing.isSecure)
    }

    @Test
    fun `legacy file context matches do not affect the KSU result`() {
        val legacy = batches(0, 1_000_000L) + listOf(0L, 900L) +
            List(18) { 0L } + List(9) { listOf(1_500L, 0L) }.flatten() + 1_500L
        val timing = KsuTypesTimingProbe.interpret(legacy)

        assertEquals(true, timing.isSecure)
        assertEquals("A>B: ksu 0/13500", timing.status)
        assertFalse(timing.details.orEmpty().contains("ksu_file"))
    }

    private fun countPayload(domainSlower: Long): List<Long> =
        List(9) { 0L } + 0L + List(9) { listOf(domainSlower, 100L) }.flatten() + 1_500L

    private fun batches(domainNs: Long, fileNs: Long): MutableList<Long> =
        (List(9) { domainNs } + List(9) { fileNs }).toMutableList()
}
