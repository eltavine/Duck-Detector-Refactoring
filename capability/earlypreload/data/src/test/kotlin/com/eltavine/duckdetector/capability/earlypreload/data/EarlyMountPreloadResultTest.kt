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

package com.eltavine.duckdetector.capability.earlypreload.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EarlyMountPreloadResultTest {
    @Test
    fun `mount id observations normalize as info for native and intent captures`() {
        for (source in listOf(EarlyMountPreloadSource.NATIVE, EarlyMountPreloadSource.INTENT)) {
            for (findings in listOf(emptyList(), listOf("MOUNT_ID_GAP|Missing 8 mount IDs|DANGER"))) {
                val result = EarlyMountPreloadResult(
                    hasRun = true, mountIdGapDetected = true, source = source, findings = findings,
                ).normalize()

                assertFalse(result.hasDangerSignal)
                assertFalse(result.hasWarningSignal)
                assertEquals(1, result.findingCount)
                assertTrue(result.findings.single().endsWith("|INFO"))
                assertTrue(result.detected)
            }
        }
    }

    @Test
    fun `mount id observation preserves the classification of other preload signals`() {
        val danger = EarlyMountPreloadResult(
            hasRun = true, mountIdGapDetected = true, mntStringsDetected = true,
        ).normalize()
        val warning = EarlyMountPreloadResult(
            hasRun = true, mountIdGapDetected = true, minorDevGapDetected = true,
            peerGroupGapDetected = true, futileHideDetected = true,
        ).normalize()

        assertTrue(danger.hasDangerSignal)
        assertTrue(danger.findings.any { it == "MNT_STRINGS|MntStrings|DANGER" })
        assertFalse(warning.hasDangerSignal)
        assertFalse(warning.hasWarningSignal)
        assertTrue(warning.findings.all { it.endsWith("|INFO") })
    }
}
