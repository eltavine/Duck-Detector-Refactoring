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
import org.junit.Assert.assertThrows
import org.junit.Test

class KernelSuTimingNativeBridgeTest {
    private val bridge = KernelSuTimingNativeBridge()

    @Test fun `unsigned ticks and frequency retain all bits`() {
        val raw = longArrayOf(0, 2, -1, 1) + LongArray(60000) { -1 }
        val result = bridge.parse(raw, false)
        assertEquals(ULong.MAX_VALUE, result.frequency)
        assertEquals(ULong.MAX_VALUE, result.vectors.last().last())
        assertEquals(KernelSuTimingCoreStatus.MEASURED, result.status)
        assertEquals(2, result.actualCpu)
    }

    @Test fun `malformed and inconsistent windows are rejected`() {
        for (raw in listOf(longArrayOf(), longArrayOf(0, 0, 1, 1), longArrayOf(7, 0, 1, 1),
            longArrayOf(1, 0, 1, 2), longArrayOf(1, 0, 1, 1, 0),
            longArrayOf(0, 0, 0, 1) + LongArray(10000),
            longArrayOf(0, -1, 1, 1) + LongArray(10000),
            longArrayOf(0, 0, 1, 0) + LongArray(10000))) {
            assertThrows(IllegalArgumentException::class.java) { bridge.parse(raw, true) }
        }
    }

    @Test fun `unsupported has no samples and preflight accepts only one vector`() {
        assertEquals(null, bridge.parse(longArrayOf(6, -1, 0, 1), true).status)
        val raw = longArrayOf(0, 0, 1, 1) + LongArray(10000)
        assertEquals(1, bridge.parse(raw, true).vectors.size)
        assertThrows(IllegalArgumentException::class.java) { bridge.parse(raw, false) }
    }
}
