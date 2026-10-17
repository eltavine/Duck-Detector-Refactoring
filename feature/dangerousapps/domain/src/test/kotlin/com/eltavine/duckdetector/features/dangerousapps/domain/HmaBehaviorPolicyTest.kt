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

class HmaBehaviorPolicyTest {
    private val security = HmaCallOutcome.SECURITY_EXCEPTION

    @Test fun `corroborated late targets are evaluated before the catalog prefix`() {
        val packages = (1..200).map { "package$it" }
        val selected = HmaBehaviorPolicy.targetOrder(packages + packages, setOf("package200")).take(128)
        assertEquals("package200", selected.first())
        assertEquals(128, selected.distinct().size)
        assertEquals("package1", selected[1])
    }

    @Test fun `both public wrapper null conversion and early return expose missing permission checks`() {
        for (outcome in listOf(HmaCallOutcome.RETURNED, HmaCallOutcome.NAME_NOT_FOUND)) {
            val result = HmaBehaviorPolicy.exceptions(HmaCheckKind.PACKAGE_INFO_EXCEPTION,
                security, security, listOf(HmaExceptionObservation("hidden", outcome, outcome)))
            assertEquals(HmaCheckState.INCONSISTENT, result.state)
            assertEquals(listOf("hidden"), result.packages)
        }
    }

    @Test fun `permission-bearing caller cannot produce a mismatch verdict`() {
        val result = HmaBehaviorPolicy.exceptions(HmaCheckKind.BROADCAST_CROSS_USER,
            HmaCallOutcome.RETURNED, security,
            listOf(HmaExceptionObservation("hidden", HmaCallOutcome.RETURNED, HmaCallOutcome.RETURNED)))
        assertEquals(HmaCheckState.INCONCLUSIVE, result.state)
    }

    @Test fun `failed changed and unavailable calls never become evidence`() {
        for (outcome in listOf(HmaCallOutcome.FAILED, HmaCallOutcome.UNAVAILABLE, HmaCallOutcome.RETURNED)) {
            val result = HmaBehaviorPolicy.exceptions(HmaCheckKind.APPLICATION_INFO_EXCEPTION,
                security, security, listOf(HmaExceptionObservation("target", security, outcome)))
            assertEquals(HmaCheckState.INCONCLUSIVE, result.state)
            assertEquals(emptyList<String>(), result.packages)
        }
    }

    @Test fun `matching security exceptions are consistent within scope`() {
        assertEquals(HmaCheckState.CONSISTENT, HmaBehaviorPolicy.exceptions(
            HmaCheckKind.APPLICATION_INFO_EXCEPTION, security, security,
            listOf(HmaExceptionObservation("target", security, security))).state)
    }

}
