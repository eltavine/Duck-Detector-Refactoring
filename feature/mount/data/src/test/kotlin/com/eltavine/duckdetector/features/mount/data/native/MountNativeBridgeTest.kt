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

package com.eltavine.duckdetector.features.mount.data.native

import com.eltavine.duckdetector.core.native.NativeCollectionOutcome
import com.eltavine.duckdetector.core.native.NativeLibraryHandle
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import com.eltavine.duckdetector.features.mount.domain.MountAnonymousDeviceState
import org.junit.Test

class MountNativeBridgeTest {

    private val bridge = MountNativeBridge()

    @Test
    fun `anonymous device payload preserves coverage states and details`() {
        for (state in MountAnonymousDeviceState.entries) {
            val parsed = bridge.parse("AVAILABLE=1\nANON_DEVICE_STATE=${state.name}\nANON_DEVICE_DETAIL=Window 0:30..0:100; gap 0:32")
            assertEquals(state, parsed.anonymousDeviceState)
            assertTrue(parsed.anonymousDeviceDetail.contains("gap 0:32"))
        }
        assertEquals(MountAnonymousDeviceState.NOT_COLLECTED,
            bridge.parse("AVAILABLE=1").anonymousDeviceState)
        assertEquals(MountAnonymousDeviceState.NOT_COLLECTED,
            bridge.parse("AVAILABLE=1\nANON_DEVICE_STATE=FUTURE_STATE").anonymousDeviceState)
    }

    @Test
    fun `missing anonymous device evidence cannot become a successful no-gap observation`() {
        for (detail in listOf("", "\nANON_DEVICE_DETAIL=   ")) {
            val snapshot = bridge.parse("AVAILABLE=1\nANON_DEVICE_STATE=NO_GAPS$detail\nMAGISK_MOUNT=1")
            assertEquals(MountAnonymousDeviceState.UNAVAILABLE, snapshot.anonymousDeviceState)
            assertTrue(snapshot.anonymousDeviceDetail.isNotBlank())
            assertTrue(snapshot.available)
            assertTrue(snapshot.magiskMountDetected)
        }
    }

    @Test
    fun `parse reads readability flags and counters`() {
        val snapshot = bridge.parse(
            """
            AVAILABLE=1
            MOUNTS_READABLE=1
            MOUNTINFO_READABLE=1
            MAPS_READABLE=0
            ROOT_MOUNT_ARTIFACT=1
            STATX_SUPPORTED=true
            PERMISSION_TOTAL=12
            PERMISSION_DENIED=3
            PERMISSION_ACCESSIBLE=9
            MOUNT_ENTRY_COUNT=41
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.mountsReadable)
        assertFalse(snapshot.mapsReadable)
        assertTrue(snapshot.rootMountArtifactDetected)
        assertFalse(snapshot.magiskMountDetected)
        assertTrue(snapshot.statxSupported)
        assertEquals(12, snapshot.permissionTotal)
        assertEquals(3, snapshot.permissionDenied)
        assertEquals(9, snapshot.permissionAccessible)
        assertEquals(41, snapshot.mountEntryCount)
    }

    @Test
    fun `parse reads tab separated findings`() {
        val snapshot = bridge.parse(
            "AVAILABLE=1\nFINDING=OVERLAY\tDANGER\tOverlay mount\t/system\tupperdir present",
        )

        assertEquals(1, snapshot.findings.size)
        val finding = snapshot.findings.single()
        assertEquals("OVERLAY", finding.group)
        assertEquals("DANGER", finding.severity)
        assertEquals("Overlay mount", finding.label)
        assertEquals("/system", finding.value)
        assertEquals("upperdir present", finding.detail)
    }

    @Test
    fun `a payload whose availability key drifted is reported instead of read as a clean device`() {
        val collector = NativeSnapshotCollector(
            library = object : NativeLibraryHandle {
                override val isLoaded: Boolean = true
                override val loadFailureDetail: String = ""
            },
        )

        val snapshot = collector.collect(
            readPayload = { "IS_AVAILABLE=1\nMOUNTS_READABLE=1" },
            parse = bridge::parse,
            unavailable = { status -> MountNativeSnapshot(collection = status) },
        )

        assertEquals(NativeCollectionOutcome.PAYLOAD_REJECTED, snapshot.collection.outcome)
        assertTrue(snapshot.collection.detail.contains("AVAILABLE"))
        assertFalse(snapshot.collection.isTrustworthy)
    }

    @Test
    fun `parse drops findings that are missing columns`() {
        val snapshot = bridge.parse("AVAILABLE=1\nFINDING=OVERLAY\tDANGER\tOverlay mount")

        assertTrue(snapshot.findings.isEmpty())
    }

    @Test
    fun `parse ignores unknown keys instead of failing`() {
        val snapshot = bridge.parse(
            """
            AVAILABLE=1
            A_KEY_ADDED_BY_A_NEWER_NATIVE_LAYER=1
            MAGISK_MOUNT=1
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.magiskMountDetected)
    }

    @Test
    fun `blank payload reports an unavailable snapshot`() {
        val snapshot = bridge.parse("   ")

        assertFalse(snapshot.available)
        assertTrue(snapshot.findings.isEmpty())
    }

    @Test
    fun `an unloadable library is reported as unavailable with a reason`() {
        val missingLibrary = object : NativeLibraryHandle {
            override val isLoaded: Boolean = false
            override val loadFailureDetail: String = "duckdetector could not be loaded: dlopen failed"
        }

        val snapshot = MountNativeBridge(NativeSnapshotCollector(missingLibrary)).collectSnapshot()

        assertFalse(snapshot.available)
        assertEquals(NativeCollectionOutcome.LIBRARY_UNAVAILABLE, snapshot.collection.outcome)
        assertTrue(snapshot.collection.detail.contains("dlopen failed"))
        assertFalse(snapshot.collection.isTrustworthy)
    }
}
