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

package com.eltavine.duckdetector.features.systemproperties.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SystemPropertiesNativeBridgeTest {

    private val bridge = SystemPropertiesNativeBridge()

    @Test
    fun `parse reads prop area availability and findings`() {
        val snapshot = bridge.parse(
            """
            AVAILABLE=1
            PROP=ro.secure|1
            RO_SERIAL_AVAILABLE=1
            RO_SERIAL_CHECKED=7
            RO_SERIAL_FINDINGS=1
            RO_SERIAL_FINDING=ro.build.fingerprint|3|0x000002|Read-only property serial low24 was non-zero in 3/3 native libc sample(s).
            PROP_AREA_AVAILABLE=1
            PROP_AREA_CONTEXTS=4
            PROP_AREA_HOLES=3
            PROP_AREA_FINDING=u:object_r:shell_prop:s0|2|Found hole in prop area: u:object_r:shell_prop:s0
            PROP_AREA_FINDING=u:object_r:vendor_prop:s0|1|Found hole in prop area: u:object_r:vendor_prop:s0
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertEquals("1", snapshot.libcProperties["ro.secure"])
        assertTrue(snapshot.readOnlySerialAvailable)
        assertEquals(7, snapshot.readOnlySerialCheckedCount)
        assertEquals(1, snapshot.readOnlySerialFindingCount)
        assertEquals(1, snapshot.readOnlySerialFindings.size)
        assertEquals("ro.build.fingerprint", snapshot.readOnlySerialFindings.first().property)
        assertEquals("0x000002", snapshot.readOnlySerialFindings.first().low24Hex)
        assertTrue(snapshot.propAreaAvailable)
        assertEquals(4, snapshot.propAreaContextCount)
        assertEquals(3, snapshot.propAreaHoleCount)
        assertEquals(2, snapshot.propAreaFindings.size)
        assertEquals("u:object_r:shell_prop:s0", snapshot.propAreaFindings.first().context)
        assertEquals(2, snapshot.propAreaFindings.first().holeCount)
    }

    @Test
    fun `blank raw output returns empty snapshot`() {
        val snapshot = bridge.parse("")

        assertFalse(snapshot.available)
        assertFalse(snapshot.readOnlySerialAvailable)
        assertEquals(0, snapshot.readOnlySerialCheckedCount)
        assertTrue(snapshot.readOnlySerialFindings.isEmpty())
        assertFalse(snapshot.propAreaAvailable)
        assertEquals(0, snapshot.propAreaContextCount)
        assertTrue(snapshot.propAreaFindings.isEmpty())
    }

    @Test
    fun `malformed prop area finding is ignored`() {
        val snapshot = bridge.parse(
            """
            AVAILABLE=1
            RO_SERIAL_AVAILABLE=1
            RO_SERIAL_CHECKED=3
            RO_SERIAL_FINDINGS=1
            RO_SERIAL_FINDING=broken
            PROP_AREA_AVAILABLE=1
            PROP_AREA_CONTEXTS=2
            PROP_AREA_HOLES=1
            PROP_AREA_FINDING=broken
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.readOnlySerialAvailable)
        assertEquals(3, snapshot.readOnlySerialCheckedCount)
        assertEquals(1, snapshot.readOnlySerialFindingCount)
        assertTrue(snapshot.readOnlySerialFindings.isEmpty())
        assertTrue(snapshot.propAreaAvailable)
        assertEquals(2, snapshot.propAreaContextCount)
        assertEquals(1, snapshot.propAreaHoleCount)
        assertTrue(snapshot.propAreaFindings.isEmpty())
    }

    @Test
    fun `callback required libc message is sanitized as unavailable`() {
        val snapshot = bridge.parse(
            """
            AVAILABLE=1
            PROP=ro.system.build.fingerprint|Must use __system_property_read_callback() to read
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertEquals("", snapshot.libcValue("ro.system.build.fingerprint"))
        assertEquals(0, snapshot.nativePropertyHitCount)
    }
}
