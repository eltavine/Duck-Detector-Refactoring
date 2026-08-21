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

package com.eltavine.duckdetector.features.mount.data.zygotenext

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ZygoteNextPayloadCodecTest {

    @Test
    fun `versioned payload decodes repeated escaped marker records`() {
        val snapshot = ZygoteNextPayloadCodec.decode(
            """
            VERSION=2
            AVAILABLE=1
            PID=42
            PPID=7
            UID=99001
            MOUNT_NAMESPACE=4026531841
            ROOT_PROPAGATION=shared:1
            ROOT_MOUNT_ID=24
            MIN_MOUNT_ID=24
            MAX_MOUNT_ID=131
            MOUNTINFO_READABLE=1
            MOUNT_COUNT=123
            ERROR=
            MARKER=KernelSU,data/adb	/data/adb/modules/example	/	ext4	/dev/block/loop7	10 1 7:0 / /data/adb/modules/example rw - ext4 /dev/block/loop7 rw
            MARKER=debug_ramdisk	/debug_ramdisk	/	tmpfs	tmpfs	11 1 0:1 / /debug_ramdisk rw - tmpfs tmpfs rw\ncontext
            """.trimIndent().replace("\\t", "\t"),
        )

        assertTrue(snapshot.available)
        assertEquals(42, snapshot.pid)
        assertEquals("shared:1", snapshot.rootPropagation)
        assertEquals(24L, snapshot.rootMountId)
        assertEquals(24L, snapshot.minimumMountId)
        assertEquals(131L, snapshot.maximumMountId)
        assertEquals(2, snapshot.markers.size)
        assertEquals(listOf("KernelSU", "data/adb"), snapshot.markers[0].labels)
        assertTrue(snapshot.markers[0].dangerous)
        assertFalse(snapshot.markers[1].dangerous)
        assertTrue(snapshot.markers[1].rawLine.contains('\n'))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `unknown payload version is rejected`() {
        ZygoteNextPayloadCodec.decode(
            """
            VERSION=3
            AVAILABLE=1
            MOUNTINFO_READABLE=1
            """.trimIndent(),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `malformed marker is rejected`() {
        ZygoteNextPayloadCodec.decode(
            """
            VERSION=2
            AVAILABLE=1
            PID=42
            PPID=7
            UID=99001
            MOUNT_NAMESPACE=1
            ROOT_PROPAGATION=shared:1
            MOUNTINFO_READABLE=1
            MOUNT_COUNT=1
            MARKER=Magisk	/too/few/fields
            """.trimIndent(),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `duplicate scalar field is rejected`() {
        ZygoteNextPayloadCodec.decode(
            """
            VERSION=2
            VERSION=2
            AVAILABLE=0
            MOUNTINFO_READABLE=0
            """.trimIndent(),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `unknown escape is rejected`() {
        ZygoteNextPayloadCodec.decode(
            """
            VERSION=2
            AVAILABLE=0
            MOUNTINFO_READABLE=0
            ERROR=bad\qescape
            """.trimIndent(),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `incomplete ready snapshot is rejected`() {
        ZygoteNextPayloadCodec.decode(
            """
            VERSION=2
            AVAILABLE=1
            PID=42
            PPID=7
            UID=99001
            MOUNT_NAMESPACE=0
            ROOT_PROPAGATION=shared:1
            MOUNTINFO_READABLE=1
            MOUNT_COUNT=0
            ERROR=
            """.trimIndent(),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `root mount id outside reported range is rejected`() {
        ZygoteNextPayloadCodec.decode(
            """
            VERSION=2
            AVAILABLE=1
            PID=42
            PPID=7
            UID=99001
            MOUNT_NAMESPACE=1
            ROOT_PROPAGATION=shared:1
            ROOT_MOUNT_ID=240
            MIN_MOUNT_ID=20
            MAX_MOUNT_ID=210
            MOUNTINFO_READABLE=1
            MOUNT_COUNT=100
            ERROR=
            """.trimIndent(),
        )
    }

    @Test
    fun `api 36 reports unsupported without collecting local state`() = runBlocking {
        var collected = false
        val manager = ZygoteNextProbeManager(
            sdkIntProvider = { 36 },
            localProbe = object : ZygoteNextLocalProbe() {
                override fun collect(): ZygoteNextProcessSnapshot {
                    collected = true
                    return ZygoteNextProcessSnapshot(available = true)
                }
            },
        )

        val result = manager.collect()

        assertEquals(ZygoteNextProbeState.UNSUPPORTED, result.state)
        assertFalse(collected)
    }

    @Test
    fun `api 37 without application context reports unavailable`() = runBlocking {
        val manager = ZygoteNextProbeManager(
            sdkIntProvider = { 37 },
            localProbe = object : ZygoteNextLocalProbe() {
                override fun collect(): ZygoteNextProcessSnapshot {
                    return ZygoteNextProcessSnapshot(
                        available = true,
                        rootPropagation = "master:1",
                    )
                }
            },
        )

        val result = manager.collect()

        assertEquals(ZygoteNextProbeState.UNAVAILABLE, result.state)
        assertEquals("master:1", result.mainProcess.rootPropagation)
    }
}
