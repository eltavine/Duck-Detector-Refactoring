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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxNativeAuditBridgeTest {

    private val bridge = SelinuxNativeAuditBridge()

    @Test
    fun `parse decodes callback lines and flags`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                CALLBACK_INSTALLED=1
                PROBE_RAN=1
                DENIAL_OBSERVED=1
                ALLOW_OBSERVED=0
                PROBE_MARKER=ddprobe_1_1
                FAILURE_REASON=Direct\ncallback
                LINE=type=1400 audit(0.0:123): avc: denied { write } for scontext=u:r:untrusted_app:s0:c1,c2 tcontext=u:object_r:system_file:s0 tclass=file
                LINE=second\tline
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.callbackInstalled)
        assertTrue(snapshot.probeRan)
        assertTrue(snapshot.denialObserved)
        assertEquals("ddprobe_1_1", snapshot.probeMarker)
        assertEquals("Direct\ncallback", snapshot.failureReason)
        assertEquals(2, snapshot.callbackLines.size)
        assertTrue(snapshot.callbackLines.first().contains("avc: denied"))
        assertEquals("second\tline", snapshot.callbackLines.last())
    }
}
