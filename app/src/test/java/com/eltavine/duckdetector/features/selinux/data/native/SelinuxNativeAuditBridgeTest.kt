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

package com.eltavine.duckdetector.features.selinux.data.native

import com.eltavine.duckdetector.core.native.NativeCollectionOutcome
import com.eltavine.duckdetector.core.native.NativeLibraryHandle
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxNativeAuditBridgeTest {

    private val bridge = SelinuxNativeAuditBridge()

    @Test
    fun `parse reads the audit callback state`() {
        val snapshot = bridge.parse(
            """
            AVAILABLE=1
            CALLBACK_INSTALLED=1
            PROBE_RAN=1
            DENIAL_OBSERVED=1
            ALLOW_OBSERVED=0
            PROBE_MARKER=duckdetector-audit-probe
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.callbackInstalled)
        assertTrue(snapshot.probeRan)
        assertTrue(snapshot.denialObserved)
        assertFalse(snapshot.allowObserved)
        assertEquals("duckdetector-audit-probe", snapshot.probeMarker)
    }

    @Test
    fun `parse restores escaped newlines and tabs in callback lines`() {
        val snapshot = bridge.parse(
            "AVAILABLE=1\nLINE=avc: denied { read } for pid=1\\tcomm=\"duck\"\\nscontext=u:r:app:s0",
        )

        assertEquals(1, snapshot.callbackLines.size)
        assertEquals(
            "avc: denied { read } for pid=1\tcomm=\"duck\"\nscontext=u:r:app:s0",
            snapshot.callbackLines.single(),
        )
    }

    @Test
    fun `parse restores an escaped backslash without inventing a newline`() {
        // The native side sends backslash, backslash, n for a literal backslash followed by 'n'.
        val snapshot = bridge.parse(
            """
            AVAILABLE=1
            FAILURE_REASON=path C:\\not-a-newline
            """.trimIndent(),
        )

        assertEquals("""path C:\not-a-newline""", snapshot.failureReason)
    }

    @Test
    fun `parse keeps every callback line in order`() {
        val snapshot = bridge.parse(
            """
            AVAILABLE=1
            LINE=first
            LINE=second
            LINE=third
            """.trimIndent(),
        )

        assertEquals(listOf("first", "second", "third"), snapshot.callbackLines)
    }

    @Test
    fun `blank payload reports an unavailable snapshot`() {
        val snapshot = bridge.parse("")

        assertFalse(snapshot.available)
        assertTrue(snapshot.callbackLines.isEmpty())
    }

    @Test
    fun `an unloadable library is named in the failure reason`() {
        val snapshot = SelinuxNativeAuditBridge(
            NativeSnapshotCollector(
                object : NativeLibraryHandle {
                    override val isLoaded: Boolean = false
                    override val loadFailureDetail: String = "duckdetector could not be loaded"
                },
            ),
        ).collectSnapshot()

        assertEquals(NativeCollectionOutcome.LIBRARY_UNAVAILABLE, snapshot.collection.outcome)
        assertTrue(snapshot.failureReason.orEmpty().contains("could not be loaded"))
        assertFalse(snapshot.collection.isTrustworthy)
    }

    @Test
    fun `a bridge that cannot be called is told apart from a clean scan`() {
        // Claim the library loaded so the collector proceeds to the JNI call, which on the host JVM
        // raises UnsatisfiedLinkError. An all-false snapshot with no reason would otherwise present
        // a probe that never ran as a device with no SELinux denials.
        val snapshot = SelinuxNativeAuditBridge(
            NativeSnapshotCollector(
                object : NativeLibraryHandle {
                    override val isLoaded: Boolean = true
                    override val loadFailureDetail: String = ""
                },
            ),
        ).collectSnapshot()

        assertEquals(NativeCollectionOutcome.BRIDGE_FAILED, snapshot.collection.outcome)
        assertTrue(snapshot.failureReason.orEmpty().contains("UnsatisfiedLinkError"))
        assertFalse(snapshot.collection.isTrustworthy)
    }
}
