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
import com.eltavine.duckdetector.testhelpers.clean.NeutralExceptionHandler
import com.eltavine.duckdetector.testhelpers.suspicious.LsposedInjectedHandler
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LSPosedHookCallbackProbeTest {

    private val probe = LSPosedHookCallbackProbe()

    @Test
    fun `lsposed named default handler reports danger`() {
        val originalHandler = Thread.getDefaultUncaughtExceptionHandler()
        try {
            Thread.setDefaultUncaughtExceptionHandler(LsposedInjectedHandler())

            val result = probe.run()

            assertEquals(1, result.hitCount)
            assertEquals(LSPosedSignalSeverity.DANGER, result.signals.single().severity)
            assertTrue(result.signals.single().detail.contains("LsposedInjectedHandler"))
        } finally {
            Thread.setDefaultUncaughtExceptionHandler(originalHandler)
        }
    }

    @Test
    fun `clean handler stays clear`() {
        val result = probe.evaluate(NeutralExceptionHandler())

        assertTrue(result.signals.isEmpty())
        assertEquals(0, result.hitCount)
    }
}
