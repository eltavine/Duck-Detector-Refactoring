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

package com.eltavine.duckdetector.features.nativeroot.data.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ThroneHuntCarrierPayloadCodecTest {

    @Test
    fun `state round trips through the payload`() {
        val state = ThroneHuntCarrierState(
            watchInstalled = true,
            watchDescriptor = 9,
            packageDirectory = "/data/app/~~a==/com.eltavine.duckdetector-b==",
            notes = listOf("note one"),
        )

        val decoded = ThroneHuntCarrierPayloadCodec.decode(
            ThroneHuntCarrierPayloadCodec.encode(state)
        )

        assertTrue(decoded.watchInstalled)
        assertEquals(9, decoded.watchDescriptor)
        assertEquals(state.packageDirectory, decoded.packageDirectory)
        assertNull(decoded.failureReason)
        assertEquals(listOf("note one"), decoded.notes)
    }

    @Test
    fun `failure reason survives escaping`() {
        val state = ThroneHuntCarrierState(
            failureReason = "line one\nline two",
        )

        val decoded = ThroneHuntCarrierPayloadCodec.decode(
            ThroneHuntCarrierPayloadCodec.encode(state)
        )

        assertFalse(decoded.watchInstalled)
        assertEquals("line one\nline two", decoded.failureReason)
    }

    @Test
    fun `blank payload decodes to an unavailable state`() {
        val decoded = ThroneHuntCarrierPayloadCodec.decode("")

        assertFalse(decoded.watchInstalled)
        assertEquals(-1, decoded.watchDescriptor)
    }

    @Test
    fun `event counts and watch denial survive the payload`() {
        val state = ThroneHuntCarrierState(
            watchInstalled = true,
            watchDescriptor = 4,
            directoryOpenCount = 3,
            directoryAccessCount = 2,
        )

        val decoded = ThroneHuntCarrierPayloadCodec.decode(
            ThroneHuntCarrierPayloadCodec.encode(state)
        )

        assertTrue(decoded.watchInstalled)
        assertEquals(3, decoded.directoryOpenCount)
        assertEquals(2, decoded.directoryAccessCount)
        assertFalse(decoded.watchDenied)
    }

    @Test
    fun `a denied watch is distinguishable from a clean round`() {
        val decoded = ThroneHuntCarrierPayloadCodec.decode(
            ThroneHuntCarrierPayloadCodec.encode(
                ThroneHuntCarrierState(
                    failureReason = "inotify_add_watch failed: Permission denied (errno=13)",
                )
            )
        )

        assertTrue(decoded.watchDenied)
        assertFalse(decoded.watchInstalled)
    }
}
