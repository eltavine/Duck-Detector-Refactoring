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

import com.eltavine.duckdetector.features.dangerousapps.domain.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

class HmaBroadcastComparisonProbeTest {
    private val normal = HmaCallbackObservation(true, payloadPreserved = true, intentPreserved = true)
    private val timeout = HmaCallbackObservation(false, failure = HmaCallbackFailure.TIMED_OUT)

    @Test fun `every target pair has caller controls before between and after`() = runTest {
        val calls = mutableListOf<String>()
        val result = HmaBroadcastComparisonProbe().run("caller", listOf("a", "b")) {
            calls += it
            normal
        }
        assertEquals(listOf("caller", "a", "caller", "a", "caller", "b", "caller", "b", "caller"), calls)
        assertEquals(true, result.all { it.state == HmaCheckState.CONSISTENT })
    }

    @Test fun `missing resultTo delivery is sampled twice with independent caller callbacks`() = runTest {
        val result = HmaBroadcastComparisonProbe().run("caller", listOf("target")) {
            if (it == "caller") normal else timeout
        }
        assertEquals(HmaCheckState.TIMING_ANOMALY, result.single {
            it.kind == HmaCheckKind.BROADCAST_RESULT_COMPLETION }.state)
    }

    @Test fun `initial callback control failure skips all target submissions`() = runTest {
        val calls = mutableListOf<String>()
        val result = HmaBroadcastComparisonProbe().run("caller", listOf("target")) {
            calls += it
            timeout
        }
        assertEquals(listOf("caller"), calls)
        assertEquals(true, result.all { it.state == HmaCheckState.INCONCLUSIVE })
    }

    @Test fun `failed interleaved control stops further targets and suppresses the current pair`() = runTest {
        var calls = 0
        val result = HmaBroadcastComparisonProbe().run("caller", listOf("a", "b")) {
            calls++
            if (calls == 3) timeout else normal.copy(ordered = it != "caller")
        }
        assertEquals(5, calls)
        assertEquals(true, result.all { it.state == HmaCheckState.INCONCLUSIVE && it.packages.isEmpty() })
    }

    @Test fun `batch deadline discards a pair missing its trailing control`() = runTest {
        var calls = 0
        val result = HmaBroadcastComparisonProbe().run("caller", listOf("a", "b")) {
            calls++
            if (calls == 9) delay(9000)
            normal
        }
        assertEquals(true, result.all { it.state == HmaCheckState.PARTIAL && it.packages.isEmpty() })
    }

    @Test fun `external cancellation propagates rather than producing timeout evidence`() = runTest {
        var returned = false
        val job = launch {
            HmaBroadcastComparisonProbe().run("caller", listOf("target")) {
                if (it == "target") throw CancellationException("cancelled")
                normal
            }
            returned = true
        }
        job.join()
        assertEquals(true, job.isCancelled)
        assertEquals(false, returned)
    }

    @Test fun `deadline before the first completed pair is explicit partial coverage`() = runTest {
        val result = HmaBroadcastComparisonProbe().run("caller", listOf("target")) {
            if (it == "target") delay(9000)
            normal
        }
        assertEquals(true, result.all { it.state == HmaCheckState.PARTIAL && it.packages.isEmpty() })
    }
}
