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

package com.eltavine.duckdetector.features.selinux.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import org.junit.Assert.assertEquals
import org.junit.Test

class SelinuxSidtabReadingTest {
    @Test fun `two paired discrepancies are a warning bounded to observation`() {
        val value = reading(true)
        assertEquals(SelinuxSidtabVerdict.DISCREPANCY_OBSERVED, value.verdict)
        assertEquals(DetectorStatus.warning(), value.status)
    }

    @Test fun `stock and synchronized query registration leave only a non-proving observation`() {
        assertEquals(SelinuxSidtabVerdict.NOT_OBSERVED, reading(false).verdict)
    }

    @Test fun `unchanged counts cannot establish context freshness`() {
        assertInconclusive { it.copy(rounds = it.rounds.map { round -> round.copy(afterAttr = round.before, afterRepeat = round.before, idleEnd = round.before) }) }
    }

    @Test fun `one discrepancy mixed with a stock round is inconclusive`() {
        val value = reading(true).copy(rounds = listOf(reading(true).rounds[0], reading(false).rounds[1]))
        assertEquals(SelinuxSidtabVerdict.INCONCLUSIVE, value.verdict)
    }

    @Test fun `background growth decreases and unstable controls cannot become findings`() {
        val mutations: List<(SelinuxSidtabRound) -> SelinuxSidtabRound> = listOf(
            { it.copy(beforeControls = it.before!! - 1) },
            { it.copy(afterContext = it.before!! - 1) },
            { it.copy(afterAttr = it.afterAttr!! + 1) },
            { it.copy(idleEnd = it.idleEnd!! + 1) },
            { it.copy(afterRepeat = it.afterRepeat!! + 1) },
        )
        mutations.forEach { mutate -> assertInconclusive { it.copy(rounds = it.rounds.map(mutate)) } }
        assertInconclusive { it.copy(rounds = listOf(it.rounds[0], it.rounds[1].copy(beforeControls = 999))) }
    }

    @Test fun `all controls transactions identity and canonical results must be valid`() {
        listOf<(SelinuxSidtabReading) -> SelinuxSidtabReading>(
            { it.copy(attempted = false) }, { it.copy(carrierVerified = false) },
            { it.copy(canonicalMismatch = true) }, { it.copy(identityChanged = true) },
            { it.copy(completedRounds = 1) }, { it.copy(rounds = it.rounds.take(1)) },
        ).forEach { assertInconclusive(it) }
        listOf<(SelinuxSidtabRound) -> SelinuxSidtabRound>(
            { it.copy(stockContextsVerified = false) }, { it.copy(controlsPassed = false) }, { it.copy(contextWritesAccepted = false) },
            { it.copy(attrWritesRejected = false) }, { it.copy(repeatWritesAccepted = false) },
            { it.copy(before = null) }, { it.copy(before = -1) },
            { it.copy(contexts = it.contexts.take(3)) }, { it.copy(beforeControls = Long.MAX_VALUE) },
        ).forEach { mutate -> assertInconclusive { it.copy(rounds = it.rounds.map(mutate)) } }
    }

    @Test fun `capture time is presentation metadata, not part of the verdict`() {
        assertEquals(SelinuxSidtabVerdict.DISCREPANCY_OBSERVED, reading(true).copy(capturedUptimeMs = null).verdict)
        assertEquals(SelinuxSidtabVerdict.NOT_OBSERVED, reading(false).copy(capturedUptimeMs = null).verdict)
    }

    @Test fun `duplicate candidates even between rounds cannot pass`() {
        assertInconclusive { it.copy(rounds = listOf(it.rounds[0], it.rounds[1].copy(contexts = it.rounds[0].contexts))) }
    }

    @Test fun `failure classes remain separate even with finding shaped stale rounds`() {
        val expected = mapOf(
            SelinuxSidtabCollection.NOT_COLLECTED to SelinuxSidtabVerdict.NOT_COLLECTED,
            SelinuxSidtabCollection.UNSUPPORTED to SelinuxSidtabVerdict.UNSUPPORTED,
            SelinuxSidtabCollection.PERMISSION_LIMITED to SelinuxSidtabVerdict.PERMISSION_LIMITED,
            SelinuxSidtabCollection.UNAVAILABLE to SelinuxSidtabVerdict.UNAVAILABLE,
            SelinuxSidtabCollection.INCONCLUSIVE to SelinuxSidtabVerdict.INCONCLUSIVE,
        )
        expected.forEach { (state, verdict) -> assertEquals(verdict, reading(true).copy(collection = state).verdict) }
    }

    private fun assertInconclusive(mutate: (SelinuxSidtabReading) -> SelinuxSidtabReading) {
        assertEquals(SelinuxSidtabVerdict.INCONCLUSIVE, mutate(reading(true)).verdict)
    }

    private fun reading(split: Boolean): SelinuxSidtabReading = SelinuxSidtabReading(
        collection = SelinuxSidtabCollection.COMPLETE, attempted = true, completedRounds = 2,
        carrierVerified = true, canonicalMismatch = false, identityChanged = false, capturedUptimeMs = 1000,
        collectionDetails = SelinuxSidtabCollectionDetails("FINISHED", 0, "EXITED", 0, "u:r:app_zygote:s0", 10000, 123, "6.6", null),
        rounds = (0 until 2).map { index ->
            val before = 100L + index * 4
            SelinuxSidtabRound(
                beforeControls = before, before = before,
                afterContext = before + if (split) 0 else 4, afterAttr = before + 4,
                afterRepeat = before + 4, idleEnd = before + 4, controlsPassed = true,
                contexts = (0 until 4).map { "u:r:app_zygote:s0:c${index * 4 + it}" },
                contextWritesAccepted = true, attrWritesRejected = true, repeatWritesAccepted = true, stockContextsVerified = true,
            )
        },
    )
}
