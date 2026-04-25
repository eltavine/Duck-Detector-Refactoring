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

package com.eltavine.duckdetector.features.virtualization.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VirtualizationNativeBridgeTest {

    private val bridge = VirtualizationNativeBridge()

    @Test
    fun `parses snapshot findings and counters`() {
        val snapshot = bridge.parseSnapshot(
            """
            AVAILABLE=1
            EGL_AVAILABLE=1
            EGL_VENDOR=Google
            EGL_RENDERER=gfxstream
            EGL_VERSION=OpenGL ES 3.2
            MOUNT_NAMESPACE_INODE=mnt:[4026531840]
            APEX_MOUNT_KEY=21|8:1|/|/apex|ext4|/dev/block/dm-1
            SYSTEM_MOUNT_KEY=22|8:1|/|/system|ext4|/dev/block/dm-2
            VENDOR_MOUNT_KEY=23|8:1|/|/vendor|ext4|/dev/block/dm-3
            MAP_LINE_COUNT=42
            FD_COUNT=9
            MOUNTINFO_LINE_COUNT=17
            ENVIRONMENT_HITS=2
            TRANSLATION_HITS=1
            RUNTIME_HITS=3
            FINDING=ENVIRONMENT	DANGER	ro.kernel.qemu	Guest	ro.kernel.qemu=1
            FINDING=TRANSLATION	WARNING	Mapped translation library	libndk_translation.so	/system/lib64/libndk_translation.so
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.eglAvailable)
        assertEquals("Google", snapshot.eglVendor)
        assertEquals("gfxstream", snapshot.eglRenderer)
        assertEquals("OpenGL ES 3.2", snapshot.eglVersion)
        assertEquals("mnt:[4026531840]", snapshot.mountNamespaceInode)
        assertEquals("21|8:1|/|/apex|ext4|/dev/block/dm-1", snapshot.apexMountKey)
        assertEquals("22|8:1|/|/system|ext4|/dev/block/dm-2", snapshot.systemMountKey)
        assertEquals("23|8:1|/|/vendor|ext4|/dev/block/dm-3", snapshot.vendorMountKey)
        assertEquals(42, snapshot.mapLineCount)
        assertEquals(9, snapshot.fdCount)
        assertEquals(17, snapshot.mountInfoCount)
        assertEquals(2, snapshot.environmentHitCount)
        assertEquals(1, snapshot.translationHitCount)
        assertEquals(3, snapshot.runtimeArtifactHitCount)
        assertEquals(2, snapshot.findings.size)
        assertEquals("ro.kernel.qemu", snapshot.findings.first().label)
    }

    @Test
    fun `parses trap summary`() {
        val result = bridge.parseTrap(
            """
            AVAILABLE=1
            SUPPORTED=1
            COMPLETED_ATTEMPTS=3
            SUSPICIOUS_ATTEMPTS=2
            DETAIL=trap detail
            ATTEMPT=1	attempt one
            ATTEMPT=0	attempt two
            """.trimIndent(),
        )

        assertTrue(result.available)
        assertTrue(result.supported)
        assertTrue(result.suspicious)
        assertEquals(3, result.completedAttempts)
        assertEquals(2, result.suspiciousAttempts)
        assertEquals(2, result.attempts.size)
    }

    @Test
    fun `parses sacrificial syscall pack summary`() {
        val result = bridge.parseSacrificialSyscallPack(
            """
            AVAILABLE=1
            SUPPORTED=1
            DISABLED=0
            DETAIL=pack detail
            ITEM=openat2	1	3	2	openat2 detail
            ATTEMPT=openat2	1	attempt one
            ATTEMPT=openat2	0	attempt two
            ITEM=statx	1	3	0	statx detail
            ATTEMPT=statx	0	statx attempt
            """.trimIndent(),
        )

        assertTrue(result.available)
        assertTrue(result.supported)
        assertFalse(result.disabled)
        assertEquals("pack detail", result.detail)
        assertEquals(2, result.items.size)
        assertEquals(1, result.hitCount)
        assertEquals("openat2", result.suspiciousItems.first().label)
        assertEquals(2, result.items.first().attempts.size)
    }

    @Test
    fun `blank snapshot falls back to empty`() {
        val snapshot = bridge.parseSnapshot("")
        val trap = bridge.parseTrap("")
        val pack = bridge.parseSacrificialSyscallPack("")

        assertFalse(snapshot.available)
        assertTrue(snapshot.findings.isEmpty())
        assertFalse(trap.available)
        assertFalse(trap.supported)
        assertFalse(pack.available)
        assertFalse(pack.supported)
    }
}
