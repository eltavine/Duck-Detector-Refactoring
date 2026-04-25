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

package com.eltavine.duckdetector.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DeviceBlacklistTest {

    @Test
    fun `huawei manufacturer is blocked`() {
        val match = DeviceBlacklist.match(
            manufacturer = "HUAWEI",
            brand = "Huawei",
        )

        requireNotNull(match)
        assertEquals("HUAWEI devices are not supported.", match.message)
    }

    @Test
    fun `huawei brand is blocked`() {
        val match = DeviceBlacklist.match(
            manufacturer = "Honor",
            brand = "huawei",
        )

        requireNotNull(match)
        assertEquals("Honor", match.manufacturer)
    }

    @Test
    fun `non huawei device is allowed`() {
        val match = DeviceBlacklist.match(
            manufacturer = "Google",
            brand = "google",
        )

        assertNull(match)
    }
}
