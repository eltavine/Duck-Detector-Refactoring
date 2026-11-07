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

package com.eltavine.duckdetector.buildlogic

import org.gradle.api.GradleException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ReleaseVersioningTest {

    @Test
    fun `stable tags name calendar versions`() {
        assertEquals("26.10.0", stableVersionName("v26.10.0"))
        assertEquals("27.1.12", stableVersionName("v27.1.12"))
    }

    @Test
    fun `stable tags outside the calendar scheme are rejected`() {
        listOf("26.10.0", "v26.13.0", "v26.0.1", "v26.09.0", "v2026.10.0", "v26.10", "v26.10.01", "v26.10.0-rc1")
            .forEach { tag ->
                assertThrows(tag, GradleException::class.java) { stableVersionName(tag) }
            }
    }

    @Test
    fun `nightly builds name the stable release they follow`() {
        assertEquals(
            "26.10.0-nightly.5+1a2b3c4d",
            nightlyVersionName("v26.10.0-5-g1a2b3c4d", fallback = "2026.10.02-1a2b3c4d5e6f"),
        )
        assertEquals(
            "26.10.0-nightly.0+1a2b3c4d",
            nightlyVersionName("v26.10.0-0-g1a2b3c4d9f", fallback = "unused"),
        )
    }

    @Test
    fun `nightly builds without a stable tag keep the dated name`() {
        assertEquals("2026.09.30-1a2b3c4d5e6f", nightlyVersionName("unknown", "2026.09.30-1a2b3c4d5e6f"))
        assertEquals("dated", nightlyVersionName(null, "dated"))
        assertEquals("dated", nightlyVersionName("v1.0-3-g1a2b3c4d", "dated"))
    }

    @Test
    fun `APK names keep one commit hash and no plus sign`() {
        assertEquals("26.10.0", apkVersionedName("26.10.0", "1a2b3c4d"))
        assertEquals(
            "26.10.0-nightly.5-1a2b3c4d",
            apkVersionedName("26.10.0-nightly.5+1a2b3c4d", "1a2b3c4d"),
        )
        assertEquals(
            "2026.09.30-1a2b3c4d5e6f",
            apkVersionedName("2026.09.30-1a2b3c4d5e6f", "1a2b3c4d"),
        )
        assertEquals("custom-1a2b3c4d", apkVersionedName("custom", "1a2b3c4d"))
    }

    @Test
    fun `stable version names are recognised`() {
        assertTrue(isStableVersionName("26.10.0"))
        assertFalse(isStableVersionName("26.10.0-nightly.5+1a2b3c4d"))
        assertFalse(isStableVersionName("2026.09.30-1a2b3c4d5e6f"))
    }
}
