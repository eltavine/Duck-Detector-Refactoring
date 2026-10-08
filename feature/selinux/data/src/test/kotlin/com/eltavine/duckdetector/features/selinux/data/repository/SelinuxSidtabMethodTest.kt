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

package com.eltavine.duckdetector.features.selinux.data.repository

import com.eltavine.duckdetector.capability.selinuxpolicy.data.*
import com.eltavine.duckdetector.features.selinux.domain.SelinuxSidtabVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SelinuxSidtabMethodTest {
    @Test fun `native errno evidence maps to paired discrepancy without an isSecure claim`() {
        val result = buildSidtabMethod(fixture())
        assertEquals(SelinuxSidtabVerdict.DISCREPANCY_OBSERVED, result.sidtab?.verdict)
        assertNull(result.isSecure)
        assertEquals(22, result.sidtab?.rounds?.first()?.attrNegativeErrno)
    }

    @Test fun `attr writes count as rejected only with EACCES after a passing attr control`() {
        val snapshot = fixture()
        val eperm = snapshot.copy(rounds = snapshot.rounds.map { round ->
            round.copy(samples = round.samples.map { it.copy(attrErrno = 1) })
        })
        val controlDenied = snapshot.copy(rounds = snapshot.rounds.map { it.copy(attrNegativeErrno = 13) })
        val controlMissing = snapshot.copy(rounds = snapshot.rounds.map { it.copy(attrNegativeErrno = null) })
        listOf(eperm, controlDenied, controlMissing).forEach {
            assertEquals(SelinuxSidtabVerdict.INCONCLUSIVE, buildSidtabMethod(it).sidtab?.verdict)
        }
    }

    @Test fun `signal unfinished phase and missing transactions cannot become findings`() {
        listOf(fixture().copy(signal = 9), fixture().copy(step = SelinuxSidtabStep.REPEAT),
            fixture().copy(rounds = emptyList()), fixture().copy(childEnd = SelinuxSidtabChildEnd.TIMED_OUT),
            fixture().copy(carrierContext = "u:r:isolated_app:s0"), fixture().copy(errno = 12),
        ).forEach { assertEquals(SelinuxSidtabVerdict.INCONCLUSIVE, buildSidtabMethod(it).sidtab?.verdict) }
    }

    @Test fun `contexts outside the stock carrier type cannot become findings`() {
        val snapshot = fixture()
        val malformed = snapshot.copy(rounds = snapshot.rounds.map { round ->
            round.copy(samples = round.samples.map { it.copy(context = "u:r:su:s0") })
        })
        assertEquals(SelinuxSidtabVerdict.INCONCLUSIVE, buildSidtabMethod(malformed).sidtab?.verdict)
    }

    @Test fun `no carrier observation is not collected`() {
        assertEquals(SelinuxSidtabVerdict.NOT_COLLECTED, buildSidtabMethod(SelinuxSidtabSnapshot()).sidtab?.verdict)
    }

    private fun fixture() = SelinuxSidtabSnapshot(
        collection = SelinuxSidtabCollection.COMPLETE, attempted = true, step = SelinuxSidtabStep.FINISHED,
        errno = 0, completedRounds = 2, uid = 10000, pid = 123, capturedUptimeMs = 1000, signal = 0,
        carrierContext = "u:r:app_zygote:s0", childEnd = SelinuxSidtabChildEnd.EXITED,
        rounds = (0 until 2).map { index ->
            val before = 100L + index * 4
            SelinuxSidtabRound(
                beforeControls = before, before = before, afterContext = before, afterAttr = before + 4,
                afterRepeat = before + 4, idleEnd = before + 4, positiveErrno = 0, negativeErrno = 22,
                attrNegativeErrno = 22,
                samples = (0 until 4).map { SelinuxSidtabSample("u:r:app_zygote:s0:c${index * 4 + it}", 0, 13, 0) },
            )
        },
    )
}
