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

package com.eltavine.duckdetector.features.bootloader.data.widevine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WidevineNativeBridgeTest {

    private val bridge = WidevineNativeBridge()

    @Test
    fun `successful native payload preserves both property reads`() {
        val snapshot = bridge.parse(
            arrayOf("1", "0", "L1", "0", "38497"),
        )

        assertTrue(snapshot.available)
        assertEquals(WidevinePropertyStatus.AVAILABLE, snapshot.securityLevel.status)
        assertEquals("L1", snapshot.securityLevel.value)
        assertEquals(WidevinePropertyStatus.AVAILABLE, snapshot.systemId.status)
        assertEquals("38497", snapshot.systemId.value)
    }

    @Test
    fun `native property status errors do not become property values`() {
        val snapshot = bridge.parse(
            arrayOf("1", "-10001", null, "-10002", null),
        )

        assertTrue(snapshot.available)
        assertEquals(WidevinePropertyStatus.UNSUPPORTED, snapshot.securityLevel.status)
        assertEquals(null, snapshot.securityLevel.value)
        assertEquals(-10001, snapshot.securityLevelStatusCode)
        assertEquals(WidevinePropertyStatus.UNSUPPORTED, snapshot.systemId.status)
    }

    @Test
    fun `unavailable native payload reduces coverage`() {
        val snapshot = bridge.parse(arrayOf("0", null, null, null, null))

        assertFalse(snapshot.available)
    }
}
