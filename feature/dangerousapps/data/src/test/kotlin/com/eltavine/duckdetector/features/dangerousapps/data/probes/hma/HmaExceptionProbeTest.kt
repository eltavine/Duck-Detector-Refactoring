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

package com.eltavine.duckdetector.features.dangerousapps.data.probes.hma

import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCallOutcome
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckKind
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckState
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

class HmaExceptionProbeTest {
    @Test fun `targets are repeated between caller controls`() = runTest {
        val calls = mutableListOf<String>()
        val result = HmaExceptionProbe().run(HmaCheckKind.PACKAGE_INFO_EXCEPTION, "caller", listOf("hidden")) {
            calls += it
            if (it == "caller") HmaCallOutcome.SECURITY_EXCEPTION else HmaCallOutcome.NAME_NOT_FOUND
        }
        assertEquals(listOf("caller", "hidden", "hidden", "caller"), calls)
        assertEquals(HmaCheckState.INCONSISTENT, result.state)
    }

    @Test fun `invalid control prevents target queries`() = runTest {
        val calls = mutableListOf<String>()
        val result = HmaExceptionProbe().run(HmaCheckKind.BROADCAST_CROSS_USER, "caller", listOf("target")) {
            calls += it
            HmaCallOutcome.UNAVAILABLE
        }
        assertEquals(listOf("caller", "caller"), calls)
        assertEquals(HmaCheckState.UNAVAILABLE, result.state)
    }
}
