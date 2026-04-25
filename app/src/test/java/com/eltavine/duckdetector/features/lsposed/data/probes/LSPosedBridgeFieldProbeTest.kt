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

package com.eltavine.duckdetector.features.lsposed.data.probes

import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LSPosedBridgeFieldProbeTest {

    private val probe = LSPosedBridgeFieldProbe()

    @Test
    fun `bridge fields surface as runtime evidence`() {
        val result = probe.evaluate("de.robv.android.xposed.XposedBridge")

        assertEquals(2, result.hitCount)
        assertTrue(result.signals.all { it.severity == LSPosedSignalSeverity.DANGER })
        assertTrue(result.signals.any { it.value == "disableHooks" })
        assertTrue(result.signals.any { it.value == "sHookedMethodCallbacks" })
    }

    @Test
    fun `missing bridge class stays clear`() {
        val result = probe.evaluate("de.robv.android.xposed.MissingBridge")

        assertTrue(result.signals.isEmpty())
        assertEquals(0, result.hitCount)
    }
}
