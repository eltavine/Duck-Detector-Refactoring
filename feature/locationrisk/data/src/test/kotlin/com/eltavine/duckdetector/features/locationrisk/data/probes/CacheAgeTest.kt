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

package com.eltavine.duckdetector.features.locationrisk.data.probes

import com.eltavine.duckdetector.features.locationrisk.domain.CacheAge
import org.junit.Assert.assertEquals
import org.junit.Test

class CacheAgeTest {
    @Test fun `missing timestamps stay unknown`() {
        assertEquals(CacheAge.UNKNOWN, cacheAge(0, 100))
        assertEquals(CacheAge.UNKNOWN, cacheAge(-1, 100))
    }
    @Test fun `future timestamp is not a current authentic fix`() {
        assertEquals(CacheAge.FUTURE, cacheAge(101, 100))
    }
    @Test fun `age uses monotonic threshold without overflow`() {
        assertEquals(CacheAge.RECENT, cacheAge(1, 300_000_000_001L))
        assertEquals(CacheAge.STALE, cacheAge(1, 300_000_000_002L))
        assertEquals(CacheAge.STALE, cacheAge(1, Long.MAX_VALUE))
    }
}
