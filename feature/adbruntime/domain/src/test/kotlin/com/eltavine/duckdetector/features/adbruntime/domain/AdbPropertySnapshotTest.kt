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

package com.eltavine.duckdetector.features.adbruntime.domain

import org.junit.Assert.*
import org.junit.Test

class AdbPropertySnapshotTest {
    @Test fun `property projections preserve known unknown and exact encoding semantics`() {
        assertEquals(AdbDaemonState.RUNNING, AdbPropertySnapshot(initAdbdState = "RUNNING").daemonState)
        assertEquals(AdbDaemonState.STOPPED, AdbPropertySnapshot(initAdbdState = "Stopped").daemonState)
        assertNull(AdbPropertySnapshot().daemonState)
        listOf("restarting", " stopped ", "").forEach {
            val snapshot = AdbPropertySnapshot(initAdbdState = it)
            assertEquals(AdbDaemonState.OTHER, snapshot.daemonState)
            assertEquals(it, snapshot.initAdbdState)
        }
        assertEquals(true, AdbPropertySnapshot(sysUsbState = "mtp, AdB ").usbAdbFunctionEnabled)
        assertEquals(false, AdbPropertySnapshot(sysUsbState = "adbd").usbAdbFunctionEnabled)
        assertNull(AdbPropertySnapshot().usbAdbFunctionEnabled)
        assertTrue(AdbPropertySnapshot(testHarnessMode = "1").testHarnessEnabled)
        listOf(null, "0", "true", " 1 ").forEach {
            assertFalse(AdbPropertySnapshot(testHarnessMode = it).testHarnessEnabled)
        }
    }
}
