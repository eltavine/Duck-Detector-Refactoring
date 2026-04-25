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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TimingSideChannelThresholdTest {

    @Test
    fun `diff above 0_2ms is positive`() {
        assertTrue(isPositiveTimingSideChannelDiff(diffMillis = 0.2001))
    }

    @Test
    fun `diff below minus 0_2ms is positive`() {
        assertTrue(isPositiveTimingSideChannelDiff(diffMillis = -0.2001))
    }

    @Test
    fun `diff equal to 0_2ms is not positive`() {
        assertFalse(isPositiveTimingSideChannelDiff(diffMillis = 0.2))
    }

    @Test
    fun `diff equal to minus 0_2ms is not positive`() {
        assertFalse(isPositiveTimingSideChannelDiff(diffMillis = -0.2))
    }

    @Test
    fun `diff inside symmetric threshold is not positive`() {
        assertFalse(isPositiveTimingSideChannelDiff(diffMillis = 0.1999))
    }

    private fun isPositiveTimingSideChannelDiff(diffMillis: Double): Boolean {
        return diffMillis > 0.2 || diffMillis < -0.2
    }
}
