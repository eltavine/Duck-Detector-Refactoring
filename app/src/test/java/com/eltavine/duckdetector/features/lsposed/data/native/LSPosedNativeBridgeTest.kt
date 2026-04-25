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

package com.eltavine.duckdetector.features.lsposed.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LSPosedNativeBridgeTest {

    private val bridge = LSPosedNativeBridge()

    @Test
    fun `parse decodes snapshot entries and traces`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                HEAP_AVAILABLE=1
                MAPS_HITS=2
                MAPS_SCANNED=412
                HEAP_HITS=1
                HEAP_SCANNED=4
                TRACE=MAPS	DANGER	LSPosed runtime mapping	/system/framework/lsposed.dex
                TRACE=HEAP	DANGER	Heap residual	MAPS\nKeyword sample matched in dalvik-main space
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.heapAvailable)
        assertEquals(2, snapshot.mapsHitCount)
        assertEquals(4, snapshot.heapScannedRegions)
        assertEquals(2, snapshot.traces.size)
        assertEquals("HEAP", snapshot.traces.last().group)
        assertTrue(snapshot.traces.last().detail.contains('\n'))
    }

    @Test
    fun `parse falls back safely on blank raw data`() {
        val snapshot = bridge.parse("")

        assertFalse(snapshot.available)
        assertFalse(snapshot.heapAvailable)
        assertTrue(snapshot.traces.isEmpty())
        assertEquals(0, snapshot.mapsHitCount)
    }
}
