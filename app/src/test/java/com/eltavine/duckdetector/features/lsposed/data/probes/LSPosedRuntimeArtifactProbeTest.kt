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

package com.eltavine.duckdetector.features.lsposed.data.probes

import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LSPosedRuntimeArtifactProbeTest {

    private val probe = LSPosedRuntimeArtifactProbe()

    @Test
    fun `unix fd and env hits are grouped by source`() {
        val result = probe.evaluate(
            unixContent = """
                00000000: 00000002 00000000 00010000 0001 01 12345 @jit-cache-lsposed
                00000000: 00000002 00000000 00010000 0001 01 12345 /data/user/0/com.eltavine.duckdetector/cache
            """.trimIndent(),
            fdTargets = listOf(
                "/dev/socket/lsposed_manager",
                "/proc/self/fd/1",
            ),
            environment = mapOf(
                "LD_PRELOAD" to "/system/lib64/liblsplant.so",
                "NORMAL_KEY" to "normal",
            ),
            appPackageName = "com.eltavine.duckdetector",
        )

        assertTrue(result.available)
        assertEquals(3, result.hitCount)
        assertEquals(2, result.dangerHitCount)
        assertEquals(1, result.warningHitCount)
        assertTrue(result.signals.any { it.label == "Unix sockets" && it.severity == LSPosedSignalSeverity.DANGER })
        assertTrue(result.signals.any { it.label == "File descriptors" && it.severity == LSPosedSignalSeverity.DANGER })
        assertTrue(result.signals.any { it.label == "Environment variables" && it.severity == LSPosedSignalSeverity.WARNING })
    }

    @Test
    fun `missing sources mark runtime artifacts unavailable`() {
        val result = probe.evaluate(
            unixContent = null,
            fdTargets = null,
            environment = null,
            appPackageName = "com.eltavine.duckdetector",
        )

        assertFalse(result.available)
        assertTrue(result.signals.isEmpty())
        assertTrue(result.failureReason?.contains("not readable") == true)
    }
}
