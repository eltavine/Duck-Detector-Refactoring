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

package com.eltavine.duckdetector.features.networkrisk.domain

import org.junit.Assert.*
import org.junit.Test

class ProxySourceCheckTest {
    private val configured = NetworkObservation.observed(ProxyConfiguration(ProxyKind.STATIC, 7890, 0))

    @Test fun `same endpoints and jointly absent views align within their scope`() {
        assertEquals(ProxySourceComparison.ALIGNED, compareProxySources(configured, NetworkObservation.observed(7890), true))
        assertEquals(ProxySourceComparison.ALIGNED, compareProxySources(NetworkObservation.absent(), NetworkObservation.absent(), false))
    }

    @Test fun `port host or configuration presence differences remain inconclusive`() {
        listOf(
            compareProxySources(configured, NetworkObservation.observed(7891), false),
            compareProxySources(configured, NetworkObservation.observed(7890), false),
            compareProxySources(configured, NetworkObservation.absent(), false),
            compareProxySources(NetworkObservation.absent(), NetworkObservation.observed(7890), false),
        ).forEach {
            assertEquals(ProxySourceComparison.DIFFERENT, it)
            assertEquals(ObservationState.INCONCLUSIVE, it.toObservationState())
        }
    }

    @Test fun `PAC partial data and denied reads cannot be verified as static endpoints`() {
        assertEquals(ProxySourceComparison.PAC_NOT_COMPARABLE, compareProxySources(
            NetworkObservation.observed(ProxyConfiguration(ProxyKind.PAC, 7890, 0)), NetworkObservation.observed(7890), true))
        listOf(ObservationState.PERMISSION_LIMITED, ObservationState.UNAVAILABLE, ObservationState.INCONCLUSIVE).forEach {
            assertEquals(ProxySourceComparison.SOURCE_UNAVAILABLE, compareProxySources(configured, NetworkObservation(it), true))
        }
    }
}
