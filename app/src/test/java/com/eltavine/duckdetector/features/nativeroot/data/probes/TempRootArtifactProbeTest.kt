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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TempRootArtifactProbeTest {

    private val probe = TempRootArtifactProbe()

    @Test
    fun `empty directory returns clean result`() {
        val result = probe.evaluate(emptyList())

        assertTrue(result.available)
        assertEquals(0, result.checkedCount)
        assertEquals(0, result.hitCount)
        assertFalse(result.tempRootDetected)
        assertFalse(result.cveExploitDetected)
    }

    @Test
    fun `unrelated files return clean result`() {
        val result = probe.evaluate(listOf("a", "shizuku", "shizuku_starter", "random_file.txt"))

        assertTrue(result.available)
        assertEquals(4, result.checkedCount)
        assertEquals(0, result.hitCount)
        assertFalse(result.tempRootDetected)
        assertFalse(result.cveExploitDetected)
    }

    @Test
    fun `ksud prefix match detects temp root`() {
        val result = probe.evaluate(
            listOf("a", "ksud-aarch64-linux-android", "shizuku_starter")
        )

        assertTrue(result.available)
        assertTrue(result.tempRootDetected)
        assertFalse(result.cveExploitDetected)
        assertEquals(1, result.hitCount)
        assertEquals(NativeRootFindingSeverity.DANGER, result.findings[0].severity)
        assertEquals("ksud-aarch64-linux-android", result.findings[0].value)
    }

    @Test
    fun `temp_su prefix match detects temp root`() {
        val result = probe.evaluate(listOf("temp_su.sock"))

        assertTrue(result.tempRootDetected)
        assertEquals(1, result.hitCount)
        assertEquals(NativeRootFindingSeverity.DANGER, result.findings[0].severity)
    }

    @Test
    fun `ksu-helper exact match detects temp root`() {
        val result = probe.evaluate(listOf("ksu-helper"))

        assertTrue(result.tempRootDetected)
        assertEquals(1, result.hitCount)
    }

    @Test
    fun `ksu-payload exact match detects temp root`() {
        val result = probe.evaluate(listOf("ksu-payload"))

        assertTrue(result.tempRootDetected)
        assertEquals(1, result.hitCount)
    }

    @Test
    fun `cve43499 in filename triggers CVE exploit detection case insensitive`() {
        val result = probe.evaluate(listOf("libCVE43499root.so"))

        assertTrue(result.tempRootDetected)
        assertTrue(result.cveExploitDetected)
        assertEquals(1, result.hitCount)
        assertEquals(NativeRootFindingSeverity.DANGER, result.findings[0].severity)
        assertTrue(result.findings[0].label.contains("CVE"))
    }

    @Test
    fun `cve-2026-43499 in filename triggers CVE exploit detection case insensitive`() {
        val result = probe.evaluate(listOf("CVE-2026-43499_payload"))

        assertTrue(result.tempRootDetected)
        assertTrue(result.cveExploitDetected)
        assertEquals(1, result.hitCount)
    }

    @Test
    fun `mixed case cve43499 still detected`() {
        val result = probe.evaluate(listOf("Cve43499.bin"))

        assertTrue(result.cveExploitDetected)
        assertTrue(result.tempRootDetected)
    }

    @Test
    fun `full listing from real device detects multiple artifacts`() {
        val result = probe.evaluate(
            listOf(
                "a",
                "ksud-aarch64-linux-android",
                "shizuku_starter",
                "ksu-helper",
                "ksud-s25u-kdp",
                "shizuku",
                "ksu-payload",
                "temp_su.sock",
            )
        )

        assertTrue(result.tempRootDetected)
        assertFalse(result.cveExploitDetected)
        assertEquals(5, result.hitCount)
        assertTrue(result.findings.all { it.severity == NativeRootFindingSeverity.DANGER })
    }

    @Test
    fun `cve filename among other artifacts sets both flags`() {
        val result = probe.evaluate(
            listOf("ksud-aarch64-linux-android", "cve-2026-43499", "ksu-helper")
        )

        assertTrue(result.tempRootDetected)
        assertTrue(result.cveExploitDetected)
        assertEquals(3, result.hitCount)
    }

    @Test
    fun `uppercase CVE-2026-43499 detected`() {
        val result = probe.evaluate(listOf("CVE-2026-43499"))

        assertTrue(result.cveExploitDetected)
    }

    @Test
    fun `lowercase cve-2026-43499 detected`() {
        val result = probe.evaluate(listOf("cve-2026-43499"))

        assertTrue(result.cveExploitDetected)
    }
}
