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

package com.eltavine.duckdetector.features.dangerousapps.data.probes

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OpenApkFdPackageProbeTest {

    private val probe = OpenApkFdPackageProbe()

    @Test
    fun `apk fd paths match known target package names`() {
        val result = probe.evaluate(
            fdTargets = listOf(
                "/data/app/~~abcd1234/com.termux-Qwerty==/base.apk",
                "/mnt/expand/123/app/com.omarea.vtools/split_config.arm64_v8a.apk",
                "/proc/self/fd/1",
            ),
            targetPackages = setOf("com.termux", "com.omarea.vtools"),
        )

        assertTrue(result.available)
        assertEquals(setOf("com.termux", "com.omarea.vtools"), result.detectedPackages)
        assertTrue(
            result.matchedPathsByPackage.getValue("com.termux")
                .single()
                .contains("/com.termux-Qwerty==/base.apk"),
        )
    }

    @Test
    fun `prefix collisions do not match sibling package names`() {
        val result = probe.evaluate(
            fdTargets = listOf(
                "/data/app/com.termux.api-123==/base.apk",
            ),
            targetPackages = setOf("com.termux"),
        )

        assertTrue(result.available)
        assertFalse("com.termux" in result.detectedPackages)
    }

    @Test
    fun `missing fd directory marks probe unavailable`() {
        val result = probe.evaluate(
            fdTargets = null,
            targetPackages = setOf("com.termux"),
        )

        assertFalse(result.available)
        assertTrue(result.detectedPackages.isEmpty())
    }
}
