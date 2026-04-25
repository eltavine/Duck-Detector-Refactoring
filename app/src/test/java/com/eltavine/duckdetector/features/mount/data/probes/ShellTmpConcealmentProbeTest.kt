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

package com.eltavine.duckdetector.features.mount.data.probes

import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ShellTmpConcealmentProbeTest {

    private val probe = ShellTmpConcealmentProbe()

    @Test
    fun `dedicated mount is danger`() {
        val result = probe.evaluate(
            ShellTmpObservation(
                parentAccessible = true,
                accessState = ShellTmpAccessState.ACCESSIBLE,
                javaExists = true,
                javaDirectory = true,
                javaCanRead = true,
                javaListable = true,
                dedicatedMounts = listOf(
                    ShellTmpMountEntry(
                        target = "/data/local/tmp",
                        fsType = "overlay",
                        source = "tmpfs",
                    ),
                ),
            ),
        )

        assertTrue(result.hasDanger)
        assertTrue(result.findings.any { it.label == "Shell tmp dedicated mount" })
    }

    @Test
    fun `missing tmp under visible parent is warning`() {
        val result = probe.evaluate(
            ShellTmpObservation(
                parentAccessible = true,
                accessState = ShellTmpAccessState.MISSING,
                javaExists = false,
                javaDirectory = false,
                javaCanRead = false,
                javaListable = false,
                dedicatedMounts = emptyList(),
            ),
        )

        assertTrue(result.hasWarning)
        assertEquals(
            MountFindingSeverity.WARNING,
            result.findings.single { it.label == "Shell tmp view" }.severity
        )
    }

    @Test
    fun `java hidden while stat accessible is danger`() {
        val result = probe.evaluate(
            ShellTmpObservation(
                parentAccessible = true,
                accessState = ShellTmpAccessState.ACCESSIBLE,
                javaExists = false,
                javaDirectory = false,
                javaCanRead = false,
                javaListable = false,
                dedicatedMounts = emptyList(),
            ),
        )

        assertTrue(result.hasDanger)
        assertTrue(result.findings.any { it.label == "Shell tmp API mismatch" })
    }

    @Test
    fun `clean observation stays clean`() {
        val result = probe.evaluate(
            ShellTmpObservation(
                parentAccessible = true,
                accessState = ShellTmpAccessState.ACCESSIBLE,
                javaExists = true,
                javaDirectory = true,
                javaCanRead = true,
                javaListable = true,
                dedicatedMounts = emptyList(),
            ),
        )

        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `java unreadable shell tmp stays clean on normal app baseline`() {
        val result = probe.evaluate(
            ShellTmpObservation(
                parentAccessible = true,
                accessState = ShellTmpAccessState.ACCESSIBLE,
                javaExists = true,
                javaDirectory = true,
                javaCanRead = false,
                javaListable = false,
                dedicatedMounts = emptyList(),
            ),
        )

        assertTrue(result.findings.isEmpty())
    }
}
