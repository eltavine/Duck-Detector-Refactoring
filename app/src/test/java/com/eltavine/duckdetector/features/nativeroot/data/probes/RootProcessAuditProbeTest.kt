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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RootProcessAuditProbeTest {

    private val probe = RootProcessAuditProbe()

    @Test
    fun `allowlisted root process is ignored`() {
        val finding = probe.toFinding(
            RootProcessSample(
                pid = 1,
                name = "init",
                uid = 0,
                gid = 0,
                statmPages = 1024,
            ),
        )

        assertNull(finding)
    }

    @Test
    fun `root manager token yields danger`() {
        val finding = probe.toFinding(
            RootProcessSample(
                pid = 777,
                name = "magiskd",
                uid = 0,
                gid = 0,
                statmPages = 2048,
                cmdline = "/data/adb/magisk/magiskd",
            ),
        )

        requireNotNull(finding)
        assertEquals("Root manager process", finding.label)
        assertEquals(NativeRootFindingSeverity.DANGER, finding.severity)
    }

    @Test
    fun `unexpected root process yields warning`() {
        val result = probe.evaluate(
            samples = listOf(
                RootProcessSample(
                    pid = 888,
                    name = "mysteryd",
                    uid = 0,
                    gid = 2000,
                    statmPages = 1024,
                ),
            ),
        )

        assertEquals(1, result.findings.size)
        assertEquals(NativeRootFindingSeverity.WARNING, result.findings.single().severity)
    }

    @Test
    fun `kernel thread style statm zero is skipped`() {
        val result = probe.evaluate(
            samples = listOf(
                RootProcessSample(
                    pid = 2,
                    name = "kthreadd",
                    uid = 0,
                    gid = 0,
                    statmPages = 0,
                ),
            ),
        )

        assertTrue(result.findings.isEmpty())
        assertEquals(0, result.checkedCount)
    }
}
