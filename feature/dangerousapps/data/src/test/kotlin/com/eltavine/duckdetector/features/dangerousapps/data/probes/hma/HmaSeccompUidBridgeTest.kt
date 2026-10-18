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

import com.eltavine.duckdetector.features.dangerousapps.domain.HmaSeccompUidEvidence
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class HmaSeccompUidBridgeTest {
    private fun clean() = intArrayOf(1, 0, 0, 6, 1, 3, 3, -1, -1, 0, 0, 1)

    @Test fun `a clean complete payload keeps all three queries notified`() {
        val snapshot = HmaSeccompUidBridge.parse(clean(), 10000, 10002)
        assertEquals(HmaSeccompUidBridge.INSTALLED, snapshot.installStatus)
        assertEquals(3, snapshot.queried)
        assertEquals(3, snapshot.notified)
        assertEquals(-1, snapshot.firstSuppressed)
        assertTrue(snapshot.selfNotified)
    }

    @Test fun `EBUSY and unsupported installs do not invent query scope`() {
        val busy = HmaSeccompUidBridge.parse(
            intArrayOf(1, 1, 16, 6, 1, 0, 0, -1, -1, 5, 0, 0), 10000, 19999)
        assertEquals(HmaSeccompUidBridge.FOREIGN_LISTENER, busy.installStatus)
        assertEquals(16, busy.installError)
        assertEquals(0, busy.queried)
        assertEquals(HmaSeccompUidBridge.QUERY_NOT_RUN, busy.queryOutcome)

        val unsupported = HmaSeccompUidBridge.parse(
            intArrayOf(1, 2, 22, 4, 19, 0, 0, -1, -1, 5, 0, 0), 10000, 19999)
        assertEquals(HmaSeccompUidBridge.UNSUPPORTED, unsupported.installStatus)
        assertEquals(4, unsupported.kernelMajor)
        assertEquals(19, unsupported.kernelMinor)
    }

    @Test fun `suppressed and trapped queries retain the observation`() {
        val suppressed = HmaSeccompUidBridge.parse(
            intArrayOf(1, 0, 0, 6, 1, 3, 2, 10001, 10001, 0, 0, 1), 10000, 10002)
        assertEquals(2, suppressed.notified)
        assertEquals(10001, suppressed.firstSuppressed)
        assertEquals(10001, suppressed.lastSuppressed)

        val trapped = HmaSeccompUidBridge.parse(
            intArrayOf(1, 0, 0, 6, 1, 0, 2, -1, -1, 1, 31, 1), 10000, 19999)
        assertEquals(HmaSeccompUidBridge.QUERY_TRAPPED, trapped.queryOutcome)
        assertEquals(2, trapped.notified)
        assertEquals(31, trapped.queryError)
    }

    @Test fun `reject corrupt counts and impossible state combinations`() {
        val invalid = listOf(
            intArrayOf(1, 0, 0, 6, 1, 3, 3, -1, -1, 0, 0),
            intArrayOf(2, 0, 0, 6, 1, 3, 3, -1, -1, 0, 0, 1),
            intArrayOf(1, 6, 0, 6, 1, 3, 3, -1, -1, 0, 0, 1),
            intArrayOf(1, 0, 0, -1, 1, 3, 3, -1, -1, 0, 0, 1),
            intArrayOf(1, 0, 0, 6, 1, 4, 2, 10002, 10002, 0, 0, 1),
            intArrayOf(1, 0, 0, 6, 1, 3, 4, 10002, 10002, 0, 0, 1),
            intArrayOf(1, 0, 0, 6, 1, 3, 3, -1, -1, 6, 0, 1),
            intArrayOf(1, 0, 0, 6, 1, 3, 3, -1, -1, 0, 0, 2),
            intArrayOf(1, 0, 0, 6, 1, 2, 2, -1, -1, 0, 0, 1),
            intArrayOf(1, 0, 0, 6, 1, 3, 3, 10001, -1, 0, 0, 1),
            intArrayOf(1, 0, 0, 6, 1, 3, 2, -1, -1, 0, 0, 1),
            intArrayOf(1, 1, 16, 6, 1, 1, 0, -1, -1, 5, 0, 0),
            intArrayOf(1, 0, 0, 6, 1, 0, 0, -1, -1, 5, 0, 0),
            intArrayOf(1, 0, 0, 6, 1, 1, 0, -1, -1, 1, 31, 1),
        )
        for (values in invalid) assertThrows(IllegalArgumentException::class.java) {
            HmaSeccompUidBridge.parse(values, 10000, 10002)
        }
    }

    @Test fun `observation mapping distinguishes listener suppression traps and limits`() {
        assertEquals(HmaSeccompUidEvidence.FOREIGN_LISTENER,
            UidSeccompSnapshot(installStatus = HmaSeccompUidBridge.FOREIGN_LISTENER,
                installError = 16).toObservation().evidence)
        assertEquals(HmaSeccompUidEvidence.TRAPPED_INSTALL,
            UidSeccompSnapshot(installStatus = HmaSeccompUidBridge.INSTALL_TRAPPED,
                installError = 31).toObservation().evidence)
        assertEquals(HmaSeccompUidEvidence.UNSUPPORTED,
            UidSeccompSnapshot(installStatus = HmaSeccompUidBridge.UNSUPPORTED,
                installError = 22).toObservation().evidence)
        assertEquals(HmaSeccompUidEvidence.RESTRICTED,
            UidSeccompSnapshot(installStatus = HmaSeccompUidBridge.RESTRICTED,
                installError = 13).toObservation().evidence)
        assertEquals(HmaSeccompUidEvidence.FAILED,
            UidSeccompSnapshot(installStatus = HmaSeccompUidBridge.FAILURE).toObservation().evidence)
        assertEquals(HmaSeccompUidEvidence.NONE,
            UidSeccompSnapshot(installStatus = HmaSeccompUidBridge.INSTALLED,
                queried = 3, notified = 3, selfNotified = true,
                queryOutcome = HmaSeccompUidBridge.QUERY_COMPLETE).toObservation().evidence)
        assertEquals(HmaSeccompUidEvidence.SUPPRESSED_QUERIES,
            UidSeccompSnapshot(installStatus = HmaSeccompUidBridge.INSTALLED,
                queried = 3, notified = 2, firstSuppressed = 10001, lastSuppressed = 10001,
                selfNotified = true, queryOutcome = HmaSeccompUidBridge.QUERY_COMPLETE)
                .toObservation().evidence)
        assertEquals(HmaSeccompUidEvidence.TRAPPED_QUERY,
            UidSeccompSnapshot(installStatus = HmaSeccompUidBridge.INSTALLED,
                notified = 2, queryOutcome = HmaSeccompUidBridge.QUERY_TRAPPED,
                queryError = 31, selfNotified = true).toObservation().evidence)
        assertEquals(HmaSeccompUidEvidence.INCOMPLETE,
            UidSeccompSnapshot(installStatus = HmaSeccompUidBridge.INSTALLED,
                notified = 2, queryOutcome = HmaSeccompUidBridge.QUERY_TIMEOUT,
                selfNotified = true).toObservation().evidence)
    }

    @Test fun `complete observations cannot carry syscall errors or impossible suppression bounds`() {
        val contradictory = listOf(clean().apply { this[2] = 13 }, clean().apply { this[10] = 5 },
            intArrayOf(1, 0, 0, 6, 1, 3, 0, 10001, 10001, 0, 0, 0),
            intArrayOf(1, 0, 0, 6, 1, 3, 2, 10000, 10002, 0, 0, 1))
        for (payload in contradictory) assertThrows(IllegalArgumentException::class.java) {
            HmaSeccompUidBridge.parse(payload, 10000, 10002)
        }
    }

    @Test fun `listener and trap findings require their supporting errno or signal`() {
        for (payload in listOf(intArrayOf(1, 1, 0, 6, 1, 0, 0, -1, -1, 5, 0, 0),
            intArrayOf(1, 5, 0, 6, 1, 0, 0, -1, -1, 5, 0, 0),
            intArrayOf(1, 0, 0, 6, 1, 0, 0, -1, -1, 1, 0, 0))) {
            assertThrows(IllegalArgumentException::class.java) {
                HmaSeccompUidBridge.parse(payload, 10000, 10002)
            }
        }
    }
}
