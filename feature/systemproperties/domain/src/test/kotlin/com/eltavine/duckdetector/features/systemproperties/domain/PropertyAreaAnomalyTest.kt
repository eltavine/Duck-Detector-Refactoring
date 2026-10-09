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

package com.eltavine.duckdetector.features.systemproperties.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PropertyAreaAnomalyTest {

    @Test
    fun `system then debug then radio is debug minus radio`() {
        val debug = 1_778_300_194_915_999_998L

        assertEquals(debug, orderedPropertyAreaDelta(debug, debug + 1L, 0L))
        assertEquals(1L, orderedPropertyAreaDelta(2L, 3L, 1L))
    }

    @Test
    fun `a modification time before the epoch still counts`() {
        assertEquals(1_000L, orderedPropertyAreaDelta(0L, 1L, -1_000L))
    }

    @Test
    fun `a difference that overflows is not shown`() {
        assertNull(orderedPropertyAreaDelta(Long.MAX_VALUE - 1L, Long.MAX_VALUE, -2L))
    }

    @Test
    fun `any other order has no difference`() {
        assertNull(orderedPropertyAreaDelta(5L, 5L, 5L))
        assertNull(orderedPropertyAreaDelta(2L, 3L, 4L))
        assertNull(orderedPropertyAreaDelta(4L, 3L, 1L))
    }
}
