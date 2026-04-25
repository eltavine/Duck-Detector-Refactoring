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

package com.eltavine.duckdetector.features.nativeroot.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CgroupProcessLeakNativeBridgeTest {

    private val bridge = CgroupProcessLeakNativeBridge()

    @Test
    fun `parse decodes cgroup paths and entries`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                PATH_CHECKS=32
                PATH_ACCESSIBLE=2
                PROCESS_COUNT=3
                PROC_DENIED=1
                PATH=/sys/fs/cgroup/uid_2000	2000	1	2
                PATH=/acct/uid_2000	2000	0	0
                ENTRY=/sys/fs/cgroup/uid_2000	2000	321	0	998877	1	123	0	456	0	0	0	0	u:r:su:s0	lspd\tdaemon	/system/bin/lspd\0--service
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertEquals(32, snapshot.pathCheckCount)
        assertEquals(2, snapshot.accessiblePathCount)
        assertEquals(3, snapshot.processCount)
        assertEquals(1, snapshot.procDeniedCount)
        assertEquals(2, snapshot.paths.size)
        assertEquals(1, snapshot.entries.size)
        assertEquals(998877L, snapshot.entries.single().startTimeTicks)
        assertEquals(1, snapshot.entries.single().killErrno)
        assertEquals(123, snapshot.entries.single().sid)
        assertEquals(456, snapshot.entries.single().pgid)
        assertEquals(0, snapshot.entries.single().schedulerPolicy)
        assertEquals(0, snapshot.entries.single().pidfdErrno)
        assertEquals("u:r:su:s0", snapshot.entries.single().procContext)
        assertEquals("lspd\tdaemon", snapshot.entries.single().comm)
        assertEquals("/system/bin/lspd\u0000--service", snapshot.entries.single().cmdline)
    }

    @Test
    fun `parse keeps legacy entry format working`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                ENTRY=/sys/fs/cgroup/uid_2000	2000	321	0	u:r:su:s0	lspd	/system/bin/lspd
            """.trimIndent(),
        )

        assertEquals(1, snapshot.entries.size)
        assertEquals("u:r:su:s0", snapshot.entries.single().procContext)
        assertEquals("lspd", snapshot.entries.single().comm)
        assertEquals("/system/bin/lspd", snapshot.entries.single().cmdline)
        assertEquals(null, snapshot.entries.single().startTimeTicks)
        assertEquals(null, snapshot.entries.single().pidfdErrno)
    }

    @Test
    fun `parse falls back safely on blank raw data`() {
        val snapshot = bridge.parse("")

        assertFalse(snapshot.available)
        assertTrue(snapshot.paths.isEmpty())
        assertTrue(snapshot.entries.isEmpty())
    }
}
