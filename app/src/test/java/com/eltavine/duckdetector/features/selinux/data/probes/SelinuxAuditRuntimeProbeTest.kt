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

package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.features.selinux.data.native.SelinuxNativeAuditBridge
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxNativeAuditSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxAuditRuntimeProbeTest {

    @Test
    fun `matching direct callback signature becomes side channel hit`() {
        val marker = "ddprobe_100_1"
        val callbackLine =
            """type=1400 audit(0.0:123): avc: denied { write } for scontext=u:r:untrusted_app:s0:c1,c2 tcontext=u:object_r:system_file:s0 tclass=file permissive=0 duckdetector_probe=$marker"""
        val result = SelinuxAuditRuntimeProbe(
            nativeBridge = FakeSelinuxNativeAuditBridge(
                SelinuxNativeAuditSnapshot(
                    available = true,
                    callbackInstalled = true,
                    probeRan = true,
                    denialObserved = true,
                    probeMarker = marker,
                    callbackLines = listOf(callbackLine),
                ),
            ),
            logcatReader = FakeSelinuxAuditLogcatReader(
                SelinuxAuditLogcatReadResult(
                    checked = true,
                    output = "03-19 12:00:00.000  1234  1234 W auditd  : $callbackLine",
                    failureReason = null,
                ),
            ),
        ).inspect()

        assertEquals(1, result.sideChannelHits.size)
        assertTrue(result.directProbeUsed)
        assertTrue(result.hits.isEmpty())
    }

    @Test
    fun `mismatched tcontext against direct callback becomes tamper hit`() {
        val marker = "ddprobe_100_2"
        val callbackLine =
            """type=1400 audit(0.0:123): avc: denied { write } for scontext=u:r:untrusted_app:s0:c1,c2 tcontext=u:object_r:system_file:s0 tclass=file permissive=0 duckdetector_probe=$marker"""
        val logcatLine =
            """03-19 12:00:00.000  1234  1234 W auditd  : type=1400 audit(0.0:124): avc: denied { write } for scontext=u:r:untrusted_app:s0:c1,c2 tcontext=u:r:priv_app:s0:c512,c768 tclass=file permissive=0 duckdetector_probe=$marker"""
        val result = SelinuxAuditRuntimeProbe(
            nativeBridge = FakeSelinuxNativeAuditBridge(
                SelinuxNativeAuditSnapshot(
                    available = true,
                    callbackInstalled = true,
                    probeRan = true,
                    denialObserved = true,
                    probeMarker = marker,
                    callbackLines = listOf(callbackLine),
                ),
            ),
            logcatReader = FakeSelinuxAuditLogcatReader(
                SelinuxAuditLogcatReadResult(
                    checked = true,
                    output = logcatLine,
                    failureReason = null,
                ),
            ),
        ).inspect()

        assertEquals(1, result.hits.size)
        assertEquals("Fake tcontext", result.hits.single().label)
    }

    @Test
    fun `unexpected allow is surfaced as runtime hit even without logcat`() {
        val result = SelinuxAuditRuntimeProbe(
            nativeBridge = FakeSelinuxNativeAuditBridge(
                SelinuxNativeAuditSnapshot(
                    available = true,
                    callbackInstalled = true,
                    probeRan = true,
                    allowObserved = true,
                ),
            ),
            logcatReader = FakeSelinuxAuditLogcatReader(
                SelinuxAuditLogcatReadResult(
                    checked = false,
                    output = "",
                    failureReason = "Recent auditd event logs are not readable from the current app context.",
                ),
            ),
        ).inspect()

        assertEquals(1, result.hits.size)
        assertEquals("Unexpected allow", result.hits.single().label)
        assertTrue(result.failureReason.orEmpty().contains("not readable"))
    }

    @Test
    fun `su related avc is surfaced separately from controlled side channel`() {
        val result = SelinuxAuditRuntimeProbe(
            nativeBridge = FakeSelinuxNativeAuditBridge(SelinuxNativeAuditSnapshot()),
            logcatReader = FakeSelinuxAuditLogcatReader(
                SelinuxAuditLogcatReadResult(
                    checked = true,
                    output =
                        """03-19 12:00:00.000  1234  1234 W auditd  : type=1400 audit(0.0:123): avc: denied { open } for comm="su" path="/proc/1/mem" scontext=u:r:untrusted_app:s0:c1,c2 tcontext=u:r:init:s0 tclass=file permissive=0""",
                    failureReason = null,
                ),
            ),
        ).inspect()

        assertTrue(result.sideChannelHits.isEmpty())
        assertEquals(1, result.suspiciousActorHits.size)
        assertEquals("comm=su", result.suspiciousActorHits.single().value)
    }

    private class FakeSelinuxNativeAuditBridge(
        private val snapshot: SelinuxNativeAuditSnapshot,
    ) : SelinuxNativeAuditBridge() {
        override fun collectSnapshot(): SelinuxNativeAuditSnapshot = snapshot
    }

    private class FakeSelinuxAuditLogcatReader(
        private val result: SelinuxAuditLogcatReadResult,
    ) : SelinuxAuditLogcatReader() {
        override fun readRecentAuditLogs(): SelinuxAuditLogcatReadResult = result
    }
}
