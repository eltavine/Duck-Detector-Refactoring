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

class ThroneHuntWatchNativeBridgeTest {

    private val bridge = ThroneHuntWatchNativeBridge()

    @Test
    fun `watch payload parses install result`() {
        val snapshot = bridge.parseWatch(
            """
            WATCH_INSTALLED=1
            WATCH_DESCRIPTOR=7
            WATCH_ERRNO=0
            WATCH_PACKAGE_DIR=/data/app/~~abc==/com.eltavine.duckdetector-def==
            WATCH_DETAIL=Watching /data/app/~~abc==/com.eltavine.duckdetector-def== for throne hunt.
            """.trimIndent(),
        )

        assertTrue(snapshot.watchInstalled)
        assertEquals(7, snapshot.watchDescriptor)
        assertEquals("/data/app/~~abc==/com.eltavine.duckdetector-def==", snapshot.packageDirectory)
        assertTrue(snapshot.detail.contains("throne hunt"))
    }

    @Test
    fun `denied watch keeps errno`() {
        val snapshot = bridge.parseWatch(
            """
            WATCH_INSTALLED=0
            WATCH_DESCRIPTOR=-1
            WATCH_ERRNO=13
            WATCH_DETAIL=inotify_add_watch denied for /data/app: Permission denied
            """.trimIndent(),
        )

        assertFalse(snapshot.watchInstalled)
        assertEquals(13, snapshot.errorNumber)
        assertTrue(snapshot.detail.contains("Permission denied"))
    }

    @Test
    fun `blank watch payload degrades to unavailable snapshot`() {
        val snapshot = bridge.parseWatch("")

        assertFalse(snapshot.watchInstalled)
        assertEquals(-1, snapshot.watchDescriptor)
    }

    @Test
    fun `event payload sums directory level opens`() {
        val summary = bridge.parseEvents(
            """
            EVENT_DIRECTORY_OPEN=1
            EVENT_DIRECTORY_ACCESS=2
            EVENT_RAW=5
            EVENT_INVALID=0
            EVENT_DETAIL=directory IN_OPEN=1 IN_ACCESS=2 raw=5
            """.trimIndent(),
        )

        assertEquals(1, summary.directoryOpenCount)
        assertEquals(2, summary.directoryAccessCount)
        assertEquals(5, summary.rawEventCount)
        assertEquals(3, summary.hitCount)
    }

    @Test
    fun `clean event payload reports zero hits`() {
        val summary = bridge.parseEvents(
            """
            EVENT_DIRECTORY_OPEN=0
            EVENT_DIRECTORY_ACCESS=0
            EVENT_RAW=0
            """.trimIndent(),
        )

        assertEquals(0, summary.hitCount)
        assertEquals(0, summary.rawEventCount)
    }
}
