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

package com.eltavine.duckdetector.features.nativeroot.data.native

import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class KernelSuTimingNativeBridgeTest {
    private val bridge = KernelSuTimingNativeBridge()
    private fun raw(preflight: Boolean, frequency: Long = 19200000, outcome: Long = -22): LongArray {
        val vectors = if (preflight) 1 else 6
        return longArrayOf(2, 0, 2, frequency, 1, 2, 2, 3, vectors.toLong()) +
            (0 until vectors).flatMap { listOf(1L, outcome, 10000L, 0L, 0L, 0L, 0L, 0L) }.toLongArray() +
            longArrayOf(vectors * 10000L) + LongArray(vectors * 10000) { -1 }
    }

    @Test fun `unsigned ticks frequency worker affinity and outcomes retain their values`() {
        val result = bridge.parse(raw(false, -1), false)
        assertEquals(ULong.MAX_VALUE, result.frequency)
        assertEquals(ULong.MAX_VALUE, result.vectors.last().last())
        assertEquals(KernelSuTimingCoreStatus.MEASURED, result.status)
        assertEquals(2, result.actualCpu)
        assertEquals(listOf(2, 3), result.allowedCpus)
        assertEquals(mapOf(-22L to 10000), result.outcomes.last().outcomes)
        assertFalse(bridge.parse(raw(true, outcome = 0), true).outcomes.single().expectedRejection)
    }

    @Test fun `malformed inconsistent and old version windows are rejected`() {
        val valid = raw(true)
        for (bad in listOf(longArrayOf(), valid.copyOf().apply { this[0] = 1 },
            valid.copyOf().apply { this[1] = 7 }, valid.copyOf().apply { this[4] = 2 },
            valid.copyOf().apply { this[3] = 0 }, valid.copyOf().apply { this[2] = -1 },
            valid.copyOf().apply { this[4] = 0 }, valid.copyOf().apply { this[7] = 2 },
            valid.copyOf().apply { this[11] = 9999 }, valid.copyOf().apply { this[15] = 4 },
            valid.dropLast(1).toLongArray(), valid + longArrayOf(0))) {
            assertThrows(IllegalArgumentException::class.java) { bridge.parse(bad, true) }
        }
        assertThrows(IllegalArgumentException::class.java) { bridge.parse(raw(true), false) }
    }

    @Test fun `unsupported and failed affinity have no timing vectors`() {
        val unsupported = longArrayOf(2, 6, -1, 0, 1, 0, 0, 0)
        assertEquals(null, bridge.parse(unsupported, true).status)
        assertEquals(KernelSuTimingCoreStatus.AFFINITY_FAILED,
            bridge.parse(unsupported.copyOf().apply { this[1] = 1 }, false).status)
    }
}
