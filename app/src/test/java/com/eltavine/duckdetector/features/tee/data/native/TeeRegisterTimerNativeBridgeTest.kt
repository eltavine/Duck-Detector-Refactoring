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

package com.eltavine.duckdetector.features.tee.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TeeRegisterTimerNativeBridgeTest {

    private val bridge = TeeRegisterTimerNativeBridge()

    @Test
    fun `parseSelection reads a successful register timer selection`() {
        val selection = bridge.parseSelection(
            """
            REGISTER_TIMER_AVAILABLE=1
            TIMER_SOURCE=cntvct_el0
            FALLBACK_REASON=
            AFFINITY=bound_cpu0
            """.trimIndent(),
        )

        assertTrue(selection.registerTimerAvailable)
        assertEquals("cntvct_el0", selection.timerSource)
        assertNull(selection.fallbackReason)
        assertEquals("bound_cpu0", selection.affinityStatus)
    }

    @Test
    fun `parseSelection keeps a non blank fallback reason`() {
        val selection = bridge.parseSelection(
            """
            REGISTER_TIMER_AVAILABLE=0
            TIMER_SOURCE=clock_monotonic
            FALLBACK_REASON=register read trapped by the kernel
            AFFINITY=not_requested
            """.trimIndent(),
        )

        assertFalse(selection.registerTimerAvailable)
        assertEquals("register read trapped by the kernel", selection.fallbackReason)
    }

    @Test
    fun `parseSelection restores escaped separators in the fallback reason`() {
        val selection = bridge.parseSelection(
            "FALLBACK_REASON=trapped\\nretried on\\tcpu0",
        )

        assertEquals("trapped\nretried on\tcpu0", selection.fallbackReason)
    }

    @Test
    fun `parseSelection falls back to documented defaults on an empty payload`() {
        val selection = bridge.parseSelection("")

        assertFalse(selection.registerTimerAvailable)
        assertEquals("clock_monotonic", selection.timerSource)
        assertEquals("not_requested", selection.affinityStatus)
        assertNull(selection.fallbackReason)
    }
}
