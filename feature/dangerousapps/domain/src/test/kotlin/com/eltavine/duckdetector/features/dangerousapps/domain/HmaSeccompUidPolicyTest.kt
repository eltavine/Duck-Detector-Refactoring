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
import org.junit.Assert.assertTrue
import org.junit.Test

class HmaSeccompUidPolicyTest {
    private fun observation(
        evidence: HmaSeccompUidEvidence,
        kernelMajor: Int = 6,
        kernelMinor: Int = 1,
        queried: Int = 10000,
        notified: Int = 10000,
        firstSuppressed: Int = -1,
        lastSuppressed: Int = -1,
        selfNotified: Boolean = true,
        detail: String = "",
    ) = HmaSeccompUidObservation(
        evidence, kernelMajor, kernelMinor, queried, notified,
        firstSuppressed, lastSuppressed, selfNotified, detail,
    )

    @Test fun `EBUSY is listener evidence only on kernels with user notification`() {
        val result = HmaSeccompUidPolicy.evaluate(observation(HmaSeccompUidEvidence.FOREIGN_LISTENER))
        assertEquals(HmaCheckState.INCONSISTENT, result.state)
        assertEquals(HmaCheckKind.SECCOMP_UID_FILTER, result.kind)
        assertTrue(result.detail.contains("EBUSY"))
        assertTrue(result.detail.contains("Kernel 6.1"))
        assertEquals(emptyList<String>(), result.packages)
        assertEquals(emptyList<Int>(), result.uids)

        val linuxFive = HmaSeccompUidPolicy.evaluate(observation(
            HmaSeccompUidEvidence.FOREIGN_LISTENER, kernelMajor = 5, kernelMinor = 0))
        assertEquals(HmaCheckState.INCONSISTENT, linuxFive.state)
    }

    @Test fun `EBUSY below Linux 5 stays inconclusive instead of claiming a listener`() {
        val result = HmaSeccompUidPolicy.evaluate(observation(
            HmaSeccompUidEvidence.FOREIGN_LISTENER, kernelMajor = 4, kernelMinor = 19))
        assertEquals(HmaCheckState.INCONCLUSIVE, result.state)
        assertTrue(result.detail.contains("not interpreted"))
    }

    @Test fun `suppressed notifications are inconsistent and keep their scope`() {
        val result = HmaSeccompUidPolicy.evaluate(observation(
            HmaSeccompUidEvidence.SUPPRESSED_QUERIES,
            queried = 10000, notified = 1, firstSuppressed = 10001, lastSuppressed = 19999,
            selfNotified = true,
        ))
        assertEquals(HmaCheckState.INCONSISTENT, result.state)
        assertTrue(result.detail.contains("9999 of 10000"))
        assertTrue(result.detail.contains("10001"))
        assertTrue(result.detail.contains("19999"))
        assertTrue(result.detail.contains("seccomp interference"))
    }

    @Test fun `only syscall-attributed query traps are positive while setup traps are limited`() {
        assertEquals(HmaCheckState.INCONSISTENT, HmaSeccompUidPolicy.evaluate(
            observation(HmaSeccompUidEvidence.TRAPPED_QUERY, queried = 0, notified = 7,
                firstSuppressed = -1, lastSuppressed = -1)
        ).state)
        assertEquals(HmaCheckState.PERMISSION_LIMITED, HmaSeccompUidPolicy.evaluate(
            observation(HmaSeccompUidEvidence.TRAPPED_INSTALL, queried = 0, notified = 0,
                firstSuppressed = -1, lastSuppressed = -1, selfNotified = false)
        ).state)
    }

    @Test fun `a clean listener run is consistent and states its limit`() {
        val result = HmaSeccompUidPolicy.evaluate(observation(HmaSeccompUidEvidence.NONE))
        assertEquals(HmaCheckState.CONSISTENT, result.state)
        assertTrue(result.detail.contains("all 10000"))
        assertTrue(result.detail.contains("seccomp filters in this process"))
    }

    @Test fun `unsupported restricted failed and incomplete remain distinct`() {
        assertEquals(HmaCheckState.UNSUPPORTED, HmaSeccompUidPolicy.evaluate(
            observation(HmaSeccompUidEvidence.UNSUPPORTED, detail = "errno 22 (EINVAL).")
        ).state)
        assertEquals(HmaCheckState.PERMISSION_LIMITED, HmaSeccompUidPolicy.evaluate(
            observation(HmaSeccompUidEvidence.RESTRICTED, detail = "errno 13 (EACCES).")
        ).state)
        assertEquals(HmaCheckState.UNAVAILABLE, HmaSeccompUidPolicy.evaluate(
            observation(HmaSeccompUidEvidence.FAILED, detail = "child ended.")
        ).state)
        assertEquals(HmaCheckState.INCONCLUSIVE, HmaSeccompUidPolicy.evaluate(
            observation(HmaSeccompUidEvidence.INCOMPLETE, queried = 0, notified = 12,
                detail = "query outcome=timeout.")
        ).state)
    }

    @Test fun `a clean label without a completed query is inconclusive`() {
        assertEquals(HmaCheckState.INCONCLUSIVE, HmaSeccompUidPolicy.evaluate(
            observation(HmaSeccompUidEvidence.NONE, queried = 0, notified = 0, selfNotified = false)
        ).state)
    }

    @Test fun `clean classification requires all notifications and the caller control`() {
        for (sample in listOf(observation(HmaSeccompUidEvidence.NONE, notified = 9999),
            observation(HmaSeccompUidEvidence.NONE, selfNotified = false))) {
            assertEquals(HmaCheckState.INCONCLUSIVE, HmaSeccompUidPolicy.evaluate(sample).state)
        }
    }
}
