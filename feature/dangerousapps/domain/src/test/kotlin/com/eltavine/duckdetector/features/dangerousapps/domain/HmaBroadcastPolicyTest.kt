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

package com.eltavine.duckdetector.features.dangerousapps.domain

import org.junit.Assert.assertEquals
import org.junit.Test

class HmaBroadcastPolicyTest {
    private val normal = HmaCallbackObservation(true, payloadPreserved = true, intentPreserved = true)
    private val timeout = HmaCallbackObservation(false, failure = HmaCallbackFailure.TIMED_OUT)
    private fun pair(first: HmaCallbackObservation, repeat: HmaCallbackObservation = first) =
        HmaCallbackComparison("target", first, repeat, normal, normal, normal)
    private fun evaluate(pair: HmaCallbackComparison, expected: Int = 1) =
        HmaBroadcastPolicy.evaluate(normal, listOf(pair), expected)
    private fun List<HmaBehaviorCheck>.check(kind: HmaCheckKind) = single { it.kind == kind }

    @Test fun `repeated timeouts with three local controls produce only lower confidence completion evidence`() {
        val checks = evaluate(pair(timeout))
        val completion = checks.check(HmaCheckKind.BROADCAST_RESULT_COMPLETION)
        assertEquals(HmaCheckState.TIMING_ANOMALY, completion.state)
        assertEquals(listOf("target"), completion.packages)
        val semantics = checks.check(HmaCheckKind.BROADCAST_RESULT_TO)
        assertEquals(HmaCheckState.INCONCLUSIVE, semantics.state)
        assertEquals(emptyList<String>(), semantics.packages)
    }

    @Test fun `one missing callback never produces a timing finding`() {
        val checks = evaluate(pair(timeout, normal))
        assertEquals(listOf(HmaCheckState.INCONCLUSIVE, HmaCheckState.INCONCLUSIVE), checks.map { it.state })
        assertEquals(true, checks.all { it.packages.isEmpty() })
    }

    @Test fun `absent callbacks without timeout observations do not imply timeout evidence`() {
        val checks = evaluate(pair(HmaCallbackObservation(false)))
        assertEquals(HmaCheckState.INCONCLUSIVE, checks.check(HmaCheckKind.BROADCAST_RESULT_COMPLETION).state)
    }

    @Test fun `failed local control suppresses timeout and semantic findings`() {
        for (target in listOf(timeout, normal.copy(ordered = true))) {
            for (observation in listOf(pair(target).copy(before = timeout),
                pair(target).copy(between = timeout), pair(target).copy(after = timeout))) {
                val checks = evaluate(observation)
                assertEquals(true, checks.all { it.state == HmaCheckState.INCONCLUSIVE && it.packages.isEmpty() })
            }
        }
    }

    @Test fun `ordered sticky result and intent mutations remain separate from callback completion`() {
        for (changed in listOf(normal.copy(ordered = true), normal.copy(sticky = true),
            normal.copy(payloadPreserved = false), normal.copy(intentPreserved = false))) {
            val checks = evaluate(pair(changed))
            assertEquals(HmaCheckState.CONSISTENT, checks.check(HmaCheckKind.BROADCAST_RESULT_COMPLETION).state)
            val semantics = checks.check(HmaCheckKind.BROADCAST_RESULT_TO)
            assertEquals(HmaCheckState.INCONSISTENT, semantics.state)
            assertEquals(listOf("target"), semantics.packages)
        }
    }

    @Test fun `single semantic difference remains inconclusive`() {
        assertEquals(HmaCheckState.INCONCLUSIVE, evaluate(pair(normal.copy(ordered = true), normal))
            .check(HmaCheckKind.BROADCAST_RESULT_TO).state)
    }

    @Test fun `failed payload decoding is unavailable rather than a semantic mismatch`() {
        val checks = evaluate(pair(normal.copy(failure = HmaCallbackFailure.FAILED)))
        assertEquals(true, checks.all { it.state == HmaCheckState.UNAVAILABLE && it.packages.isEmpty() })
    }

    @Test fun `target and control permission denials remain distinct from timeouts`() {
        val denied = HmaCallbackObservation(false, failure = HmaCallbackFailure.PERMISSION_DENIED)
        for (checks in listOf(evaluate(pair(denied)), evaluate(pair(timeout).copy(between = denied)),
            HmaBroadcastPolicy.evaluate(denied, emptyList(), 1))) {
            assertEquals(true, checks.all { it.state == HmaCheckState.PERMISSION_LIMITED && it.packages.isEmpty() })
        }
    }

    @Test fun `empty and truncated scopes cannot produce a complete clean check`() {
        assertEquals(true, HmaBroadcastPolicy.evaluate(normal, emptyList(), 1)
            .all { it.state == HmaCheckState.INCONCLUSIVE })
        assertEquals(true, evaluate(pair(normal), 4).all { it.state == HmaCheckState.PARTIAL })
    }

    @Test fun `uncontrolled package cannot inherit another packages passing controls`() {
        val checks = HmaBroadcastPolicy.evaluate(normal, listOf(
            pair(normal).copy(packageName = "passing"), pair(timeout).copy(between = timeout)), 2)
        assertEquals(true, checks.all { it.packages.isEmpty() && it.state == HmaCheckState.INCONCLUSIVE })
    }
}
