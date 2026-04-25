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
import org.junit.Assert.assertTrue
import org.junit.Test

class ShellTmpMetadataProbeTest {

    private val probe = ShellTmpMetadataProbe()

    @Test
    fun `owner and mode drift produce danger findings`() {
        val result = probe.evaluate(
            ShellTmpMetadataSample(
                uid = 0,
                gid = 0,
                mode = 0x1FF,
                inode = 512,
            ),
        )

        assertTrue(result.available)
        assertEquals(2, result.findings.count { it.severity == NativeRootFindingSeverity.DANGER })
        assertTrue(result.findings.any { it.label == "Shell tmp ownership" })
        assertTrue(result.findings.any { it.label == "Shell tmp mode" })
    }

    @Test
    fun `high inode is warning only`() {
        val result = probe.evaluate(
            ShellTmpMetadataSample(
                uid = 2000,
                gid = 2000,
                mode = 0x1F9,
                inode = 15001,
            ),
        )

        assertEquals(1, result.findings.size)
        assertEquals(NativeRootFindingSeverity.WARNING, result.findings.single().severity)
        assertEquals("Shell tmp inode", result.findings.single().label)
    }

    @Test
    fun `expected metadata stays clean`() {
        val result = probe.evaluate(
            ShellTmpMetadataSample(
                uid = 2000,
                gid = 2000,
                mode = 0x41F9,
                inode = 1024,
            ),
        )

        assertTrue(result.available)
        assertTrue(result.findings.isEmpty())
    }
}
