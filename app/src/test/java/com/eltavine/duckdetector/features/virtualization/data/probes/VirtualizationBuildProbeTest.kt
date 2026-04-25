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

package com.eltavine.duckdetector.features.virtualization.data.probes

import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VirtualizationBuildProbeTest {

    @Test
    fun `single weak token does not raise build warning`() {
        val probe = VirtualizationBuildProbe()
        val signals = probe.evaluate(
            listOf(
                "Build.FINGERPRINT" to "vendor/device/test-keys",
                "Build.PRODUCT" to "realdevice",
            ),
        )

        assertTrue(signals.none { it.label == "Generic build tokens" })
    }

    @Test
    fun `weak token cluster still raises warning`() {
        val probe = VirtualizationBuildProbe()
        val signals = probe.evaluate(
            listOf(
                "Build.FINGERPRINT" to "generic/device/test-keys",
                "Build.PRODUCT" to "unknown",
            ),
        )

        assertEquals(1, signals.size)
        assertEquals("Generic build tokens", signals.first().label)
        assertEquals(VirtualizationSignalSeverity.WARNING, signals.first().severity)
    }
}
