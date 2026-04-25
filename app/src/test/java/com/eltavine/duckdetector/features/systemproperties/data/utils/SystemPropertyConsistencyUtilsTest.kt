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

package com.eltavine.duckdetector.features.systemproperties.data.utils

import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SystemPropertyConsistencyUtilsTest {

    private val utils = SystemPropertyConsistencyUtils()

    @Test
    fun `callback placeholder is ignored for source mismatch`() {
        val signals = utils.buildSourceMismatchSignals(
            listOf(
                MultiSourcePropertyRead(
                    property = "ro.system.build.fingerprint",
                    category = SystemPropertyCategory.BUILD_FINGERPRINT,
                    preferredValue = "Xiaomi/test/device:16/BUILD/123:user/release-keys",
                    preferredSource = SystemPropertySource.REFLECTION,
                    sourceValues = linkedMapOf(
                        SystemPropertySource.REFLECTION to "Xiaomi/test/device:16/BUILD/123:user/release-keys",
                        SystemPropertySource.GETPROP to "Xiaomi/test/device:16/BUILD/123:user/release-keys",
                        SystemPropertySource.NATIVE_LIBC to "Must use __system_property_read_callback() to read",
                        SystemPropertySource.JVM to "",
                    ),
                ),
            ),
        )

        assertTrue(signals.isEmpty())
    }

    @Test
    fun `real native divergence still produces mismatch`() {
        val signals = utils.buildSourceMismatchSignals(
            listOf(
                MultiSourcePropertyRead(
                    property = "ro.boot.verifiedbootstate",
                    category = SystemPropertyCategory.VERIFIED_BOOT,
                    preferredValue = "green",
                    preferredSource = SystemPropertySource.REFLECTION,
                    sourceValues = linkedMapOf(
                        SystemPropertySource.REFLECTION to "green",
                        SystemPropertySource.GETPROP to "green",
                        SystemPropertySource.NATIVE_LIBC to "orange",
                        SystemPropertySource.JVM to "",
                    ),
                ),
            ),
        )

        assertEquals(1, signals.size)
        assertEquals(SystemPropertySource.REFLECTION, signals.single().source)
    }
}
