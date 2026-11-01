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

package com.eltavine.duckdetector.features.networkrisk.data.network

import org.junit.Assert.*
import org.junit.Test

class RepeatedNetworkSamplerTest {
    @Test fun `switch during read retries the entire sample`() {
        val values = ArrayDeque(listOf("wifi-before", "vpn-after", "vpn-after", "vpn-after"))
        val result = RepeatedNetworkSampler { values.removeFirst() }.collect()
        assertTrue(result.repeated)
        assertEquals("vpn-after", result.value)
        assertEquals(2, result.attempts)
        assertTrue(values.isEmpty())
    }

    @Test fun `continuous switching is bounded and inconclusive`() {
        var reads = 0
        val result = RepeatedNetworkSampler { reads++ }.collect()
        assertFalse(result.repeated)
        assertEquals(4, reads)
        assertEquals(3, result.value)
    }

    @Test fun `unchanged absence stays a scoped negative observation`() {
        var reads = 0
        val result = RepeatedNetworkSampler { reads++; emptyList<String>() }.collect()
        assertTrue(result.repeated)
        assertEquals(2, reads)
    }
}
