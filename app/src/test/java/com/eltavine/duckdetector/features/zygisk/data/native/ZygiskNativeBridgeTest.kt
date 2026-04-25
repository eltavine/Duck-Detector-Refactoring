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

package com.eltavine.duckdetector.features.zygisk.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ZygiskNativeBridgeTest {

    private val bridge = ZygiskNativeBridge()

    @Test
    fun `parse decodes scalar keys and traces`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                HEAP_AVAILABLE=1
                SECCOMP_SUPPORTED=1
                TRACER_PID=42
                STRONG_HITS=1
                HEURISTIC_HITS=2
                LINKER_HOOK_HITS=1
                VMAP_HITS=1
                HEAP_HITS=1
                TRACE=LINKER	DANGER	Linker hook	dlopen resolved outside linker @ 0x1234
                TRACE=HEAP	WARNING	Heap entropy	free-kept heap crossed threshold\nfordblks stayed elevated
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.heapAvailable)
        assertTrue(snapshot.seccompSupported)
        assertEquals(42, snapshot.tracerPid)
        assertEquals(1, snapshot.strongHitCount)
        assertEquals(2, snapshot.heuristicHitCount)
        assertEquals(2, snapshot.traces.size)
        assertEquals("LINKER", snapshot.traces[0].group)
        assertTrue(snapshot.traces[1].detail.contains('\n'))
    }

    @Test
    fun `parse falls back safely on blank raw data`() {
        val snapshot = bridge.parse("")

        assertFalse(snapshot.available)
        assertFalse(snapshot.heapAvailable)
        assertEquals(0, snapshot.strongHitCount)
        assertTrue(snapshot.traces.isEmpty())
    }
}
