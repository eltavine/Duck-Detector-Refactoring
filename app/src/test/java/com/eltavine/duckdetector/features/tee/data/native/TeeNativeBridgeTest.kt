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

package com.eltavine.duckdetector.features.tee.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TeeNativeBridgeTest {

    private val bridge = TeeNativeBridge()

    @Test
    fun `decodeSnapshot parses repeated methods and advanced tricky store flags`() {
        val snapshot = bridge.decodeSnapshot(
            environmentRaw = """
                TRACING=1
                PAGE_SIZE=4096
                MAPPING=/system/lib64/libfoo.so
            """.trimIndent(),
            trickyRaw = """
                DETECTED=1
                GOT_HOOK=1
                SYSCALL_MISMATCH=1
                INLINE_HOOK=0
                HONEYPOT=1
                TIMER_SOURCE=arm64_cntvct
                TIMER_FALLBACK=clock_gettime monotonic unavailable
                AFFINITY=bound_cpu0
                RUNS=3
                SUSPICIOUS_RUNS=2
                MEDIAN_GAP_NS=18420
                GAP_MAD_NS=910
                MEDIAN_NOISE_NS=10000
                MEDIAN_RATIO_PERCENT=167
                METHOD=GOT_HOOK
                METHOD=HONEYPOT
                DETAILS=hooked
            """.trimIndent(),
            derRaw = """
                PRIMARY=0
                SECONDARY=1
                FINDING=tag
            """.trimIndent(),
        )

        assertTrue(snapshot.tracingDetected)
        assertEquals(4096, snapshot.pageSize)
        assertTrue(snapshot.trickyStoreDetected)
        assertTrue(snapshot.gotHookDetected)
        assertTrue(snapshot.syscallMismatchDetected)
        assertTrue(snapshot.honeypotDetected)
        assertEquals("arm64_cntvct", snapshot.trickyStoreTimerSource)
        assertEquals("clock_gettime monotonic unavailable", snapshot.trickyStoreTimerFallbackReason)
        assertEquals("bound_cpu0", snapshot.trickyStoreAffinityStatus)
        assertEquals(3, snapshot.trickyStoreTimingRunCount)
        assertEquals(2, snapshot.trickyStoreTimingSuspiciousRunCount)
        assertEquals(18420L, snapshot.trickyStoreTimingMedianGapNs)
        assertEquals(910L, snapshot.trickyStoreTimingGapMadNs)
        assertEquals(10000L, snapshot.trickyStoreTimingMedianNoiseFloorNs)
        assertEquals(167, snapshot.trickyStoreTimingMedianRatioPercent)
        assertEquals(listOf("GOT_HOOK", "HONEYPOT"), snapshot.trickyStoreMethods)
        assertTrue(snapshot.leafDerSecondaryDetected)
    }

    @Test
    fun `decodeSnapshot falls back safely when fields are missing`() {
        val snapshot = bridge.decodeSnapshot(
            environmentRaw = "",
            trickyRaw = "DETAILS=clean",
            derRaw = "",
        )

        assertFalse(snapshot.trickyStoreDetected)
        assertFalse(snapshot.gotHookDetected)
        assertFalse(snapshot.syscallMismatchDetected)
        assertEquals("clean", snapshot.trickyStoreDetails)
        assertEquals("unknown", snapshot.trickyStoreTimerSource)
        assertEquals(null, snapshot.trickyStoreTimerFallbackReason)
        assertEquals("not_requested", snapshot.trickyStoreAffinityStatus)
        assertEquals(null, snapshot.trickyStoreTimingRunCount)
        assertEquals(null, snapshot.trickyStoreTimingSuspiciousRunCount)
        assertEquals(null, snapshot.trickyStoreTimingMedianGapNs)
        assertEquals(null, snapshot.trickyStoreTimingGapMadNs)
        assertEquals(null, snapshot.trickyStoreTimingMedianNoiseFloorNs)
        assertEquals(null, snapshot.trickyStoreTimingMedianRatioPercent)
        assertTrue(snapshot.trickyStoreMethods.isEmpty())
    }
}
