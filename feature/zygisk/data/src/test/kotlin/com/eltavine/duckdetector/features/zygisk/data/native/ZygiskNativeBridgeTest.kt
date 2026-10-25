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

package com.eltavine.duckdetector.features.zygisk.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskAtexitState

class ZygiskNativeBridgeTest {

    private val bridge = ZygiskNativeBridge()

    private fun evaluatedPayload(entries: Int = 10, cleared: Int = 0, gaps: Int = 0, callbacks: Int = 0) = """
        AVAILABLE=1
        ATEXIT_TABLE_STATE=COLLECTED
        ATEXIT_TABLE_ENTRIES=$entries
        ATEXIT_TABLE_NULLS=$cleared
        ATEXIT_TABLE_GAPS=$gaps
        ATEXIT_TABLE_CALLBACKS=$callbacks
        ATEXIT_TABLE_DETAIL=Bounded table
    """.trimIndent()

    @Test
    fun `evaluated coverage requires every count and explanation`() {
        val complete = evaluatedPayload()
        listOf("ENTRIES", "NULLS", "GAPS", "CALLBACKS", "DETAIL").forEach { field ->
            val incomplete = complete.lineSequence().filterNot { it.startsWith("ATEXIT_TABLE_$field=") }.joinToString("\n")
            assertThrows(IllegalArgumentException::class.java) { bridge.parse(incomplete) }
        }
        assertEquals(ZygiskAtexitState.COLLECTED, bridge.parse(complete).atexitTable.state)
    }

    @Test
    fun `contradictory evaluated counts are rejected`() {
        listOf(
            evaluatedPayload(entries = 0),
            evaluatedPayload(cleared = 11),
            evaluatedPayload(cleared = 3, gaps = 2),
            evaluatedPayload(cleared = 5, callbacks = 6),
        ).forEach { payload ->
            assertThrows(IllegalArgumentException::class.java) { bridge.parse(payload) }
        }
    }

    @Test
    fun `dumpability preserves zero without treating missing values as zero`() {
        assertEquals(-1, bridge.parse("AVAILABLE=1").atexitTable.dumpable)
        listOf("0", "1", "2").forEach {
            assertEquals(it.toInt(), bridge.parse("AVAILABLE=1\nATEXIT_TABLE_DUMPABLE=$it").atexitTable.dumpable)
        }
        listOf("-1", "3", "bad").forEach {
            assertEquals(-1, bridge.parse("AVAILABLE=1\nATEXIT_TABLE_DUMPABLE=$it").atexitTable.dumpable)
        }
    }

    @Test
    fun `malformed table counts do not become a zero evidence result`() {
        listOf("-1", "invalid", "999999999999999999999").forEach { count ->
            assertThrows(IllegalArgumentException::class.java) {
                bridge.parse("AVAILABLE=1\nATEXIT_TABLE_ENTRIES=$count")
            }
        }
    }

    @Test
    fun `missing unknown and unavailable table states do not become evaluated`() {
        assertEquals(ZygiskAtexitState.NOT_COLLECTED, bridge.parse("AVAILABLE=1").atexitTable.state)
        assertEquals(ZygiskAtexitState.NOT_COLLECTED, bridge.parse("AVAILABLE=1\nATEXIT_TABLE_STATE=NEW_LAYOUT").atexitTable.state)
        listOf("UNSUPPORTED", "UNAVAILABLE", "PERMISSION_DENIED", "BUSY", "INVALID").forEach { state ->
            val result = bridge.parse("AVAILABLE=1\nATEXIT_TABLE_STATE=$state")
            assertEquals(state, result.atexitTable.state.name)
            assertFalse(result.atexitTable.hasEvidence)
        }
        assertThrows(IllegalArgumentException::class.java) {
            bridge.parse("AVAILABLE=1\nATEXIT_TABLE_STATE=PARTIAL")
        }
    }

    @Test
    fun `table residue preserves counts and escaped failure details`() {
        val table = bridge.parse("""
            AVAILABLE=1
            ATEXIT_TABLE_STATE=PARTIAL
            ATEXIT_TABLE_ENTRIES=456
            ATEXIT_TABLE_NULLS=36
            ATEXIT_TABLE_GAPS=1
            ATEXIT_TABLE_CALLBACKS=2
            ATEXIT_TABLE_DETAIL=Read table\nOne unresolved callback
        """.trimIndent()).atexitTable
        assertEquals(ZygiskAtexitState.PARTIAL, table.state)
        assertEquals(456, table.entries)
        assertEquals(36, table.nullEntries)
        assertEquals(1, table.anchoredGaps)
        assertEquals(2, table.anonymousCallbacks)
        assertTrue(table.hasEvidence)
        assertEquals("Read table\nOne unresolved callback", table.detail)
    }

    @Test
    fun `parse decodes scalar keys and traces`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                HEAP_AVAILABLE=1
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

    @Test
    fun `parse decodes NeoZygisk TMP_PATH marker trace`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                STRONG_HITS=1
                TRACE=RUNTIME	DANGER	NeoZygisk environment marker	Environment contains NeoZygisk marker: TMP_PATH=/data/adb/neozygisk.
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertEquals(1, snapshot.strongHitCount)
        assertEquals(1, snapshot.traces.size)
        assertEquals("RUNTIME", snapshot.traces[0].group)
        assertEquals("DANGER", snapshot.traces[0].severity)
        assertEquals("NeoZygisk environment marker", snapshot.traces[0].label)
        assertEquals(
            "Environment contains NeoZygisk marker: TMP_PATH=/data/adb/neozygisk.",
            snapshot.traces[0].detail,
        )
    }
}
