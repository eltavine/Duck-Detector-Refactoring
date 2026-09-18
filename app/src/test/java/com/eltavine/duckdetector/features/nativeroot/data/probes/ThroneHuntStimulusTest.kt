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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ThroneHuntStimulusTest {

    @Test
    fun `every mark differs from the stored value`() {
        val encountered = listOf<Set<String>?>(
            null,
            emptySet(),
            ThroneHuntStimulus.MARK_A,
            ThroneHuntStimulus.MARK_B,
            setOf("application/some-other-group"),
        )

        encountered.forEach { current ->
            val next = ThroneHuntStimulus.nextMark(current)
            assertTrue("nextMark must produce a non-empty set", next.isNotEmpty())
            assertNotEquals(
                "an unchanged mime set is short-circuited by PackageManagerService",
                current,
                next,
            )
        }
    }

    @Test
    fun `mark flips between the two known values`() {
        assertEquals(ThroneHuntStimulus.MARK_B, ThroneHuntStimulus.nextMark(ThroneHuntStimulus.MARK_A))
        assertEquals(ThroneHuntStimulus.MARK_A, ThroneHuntStimulus.nextMark(ThroneHuntStimulus.MARK_B))
    }

    @Test
    fun `unset group still produces a real change`() {
        assertEquals(ThroneHuntStimulus.MARK_A, ThroneHuntStimulus.nextMark(null))
        assertEquals(ThroneHuntStimulus.MARK_A, ThroneHuntStimulus.nextMark(emptySet()))
    }

    // Regression guard. When the value came from a counter held in this process, every cold start
    // restarted at the same phase, so each session's first round resubmitted the value the previous
    // session ended on and produced a silent false negative instead of a rewrite.
    @Test
    fun `the choice depends only on the stored value, never on call count`() {
        repeat(4) {
            assertEquals(ThroneHuntStimulus.MARK_A, ThroneHuntStimulus.nextMark(ThroneHuntStimulus.MARK_B))
        }
        repeat(4) {
            assertEquals(ThroneHuntStimulus.MARK_B, ThroneHuntStimulus.nextMark(ThroneHuntStimulus.MARK_A))
        }
    }

    @Test
    fun `the observation window outlasts the settings write delay`() {
        assertTrue(
            ThroneHuntStimulus.SETTINGS_WRITE_WINDOW_MS > ThroneHuntStimulus.SETTINGS_WRITE_DELAY_MS,
        )
        assertEquals(
            ThroneHuntStimulus.SETTINGS_WRITE_DELAY_MS + ThroneHuntStimulus.SEARCH_MANAGER_ALLOWANCE_MS,
            ThroneHuntStimulus.SETTINGS_WRITE_WINDOW_MS,
        )
    }
}
