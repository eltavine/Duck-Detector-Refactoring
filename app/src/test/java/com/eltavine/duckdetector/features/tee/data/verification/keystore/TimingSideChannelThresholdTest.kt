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
    fun `ratio above 1_1x is positive`() {
        assertTrue(
            isPositiveTimingSideChannelRatio(
                avgAttestedMillis = 0.612,
                avgNonAttestedMillis = 0.400,
            ),
        )
    }

    @Test
    fun `ratio above 1_1x is positive regardless of direction`() {
        assertTrue(
            isPositiveTimingSideChannelRatio(
                avgAttestedMillis = 0.100,
                avgNonAttestedMillis = 0.450,
            ),
        )
    }

    @Test
    fun `ratio equal to 1_1x is not positive`() {
        assertFalse(
            isPositiveTimingSideChannelRatio(
                avgAttestedMillis = 1.10,
                avgNonAttestedMillis = 1.00,
            ),
        )
    }

    @Test
    fun `ratio inside threshold is not positive`() {
        assertFalse(
            isPositiveTimingSideChannelRatio(
                avgAttestedMillis = 1.09,
                avgNonAttestedMillis = 1.00,
            ),
        )
    }

    @Test
    fun `missing or invalid timing is not positive`() {
        assertFalse(isPositiveTimingSideChannelRatio(null, 1.00))
        assertFalse(isPositiveTimingSideChannelRatio(1.00, 0.0))
    }
}
