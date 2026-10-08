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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class SelinuxSidtabPayloadCodecTest {
    @Test fun `complete snapshot round trips nested escaping and all transaction evidence`() {
        val value = fixture()
        assertEquals(value, SelinuxSidtabPayloadCodec.decode(SelinuxSidtabPayloadCodec.encode(value)))
        val carrier = SelinuxContextValiditySnapshot(available = true, sidtab = value)
        val parsed = SelinuxContextValidityBridge().parse(SelinuxContextValidityPayloadCodec.encode(carrier))
        assertEquals(value, parsed.sidtab)
    }

    @Test fun `older carrier payload leaves the experiment not collected`() {
        val value = SelinuxContextValidityBridge().parse("AVAILABLE=1\n")
        assertEquals(SelinuxSidtabCollection.NOT_COLLECTED, value.sidtab.collection)
        assertFalse(value.sidtab.attempted)
        assertEquals(true, value.component1())
        assertEquals(true, SelinuxContextValiditySnapshot(true).available)
    }

    @Test fun `unknown duplicate truncated and malformed headers become unavailable`() {
        listOf(
            "", "SCHEMA=2\nSTATE=COMPLETE\nATTEMPTED=1\nSTEP=FINISHED\n",
            "SCHEMA=1\nSTATE=FUTURE\nATTEMPTED=1\nSTEP=FINISHED\n",
            "SCHEMA=1\nSTATE=COMPLETE\nATTEMPTED=yes\nSTEP=FINISHED\n",
            "SCHEMA=1\nSTATE=COMPLETE\nATTEMPTED=1\nSTEP=FINISHED\nSCHEMA=1\n",
            "SCHEMA=1\nSTATE=COMPLETE\nATTEMPTED=1\nSTEP=FUTURE\n",
        ).forEach { assertEquals(SelinuxSidtabCollection.UNAVAILABLE, SelinuxSidtabPayloadCodec.decode(it).collection) }
    }

    @Test fun `missing negative overflow counts remain unknown rather than zero`() {
        val wire = SelinuxSidtabPayloadCodec.encode(fixture())
        listOf("-1", "no", "9223372036854775808").forEach { invalid ->
            assertNull(SelinuxSidtabPayloadCodec.decode(wire.replace("R0_BEFORE=100", "R0_BEFORE=$invalid")).rounds[0].before)
        }
        assertNull(SelinuxSidtabPayloadCodec.decode(wire.replace("R0_BEFORE=100\n", "")).rounds[0].before)
    }

    @Test fun `malformed nested evidence does not discard other carrier observations`() {
        val value = SelinuxContextValidityBridge().parse("AVAILABLE=1\nSIDTAB_SNAPSHOT=bad\nKSU_DOMAIN_VALID=1\n")
        assertEquals(true, value.ksuDomainValid)
        assertEquals(SelinuxSidtabCollection.UNAVAILABLE, value.sidtab.collection)
    }

    @Test fun `absent safety flags and unknown child outcome cannot imply successful collection`() {
        val wire = SelinuxSidtabPayloadCodec.encode(fixture())
        val value = SelinuxSidtabPayloadCodec.decode(wire.replace("CANONICAL_MISMATCH=0\n", "").replace("IDENTITY_CHANGED=0\n", "").replace("CHILD_END=EXITED", "CHILD_END=FUTURE"))
        assertEquals(true, value.canonicalMismatch)
        assertEquals(true, value.identityChanged)
        assertNull(value.childEnd)
    }

    private fun fixture() = SelinuxSidtabSnapshot(
        collection = SelinuxSidtabCollection.COMPLETE, attempted = true, step = SelinuxSidtabStep.FINISHED,
        errno = 0, completedRounds = 2, uid = 10000, pid = 123, capturedUptimeMs = 1000,
        carrierContext = "u:r:app_zygote:s0", kernelRelease = "6.6-test\nline\\suffix", childEnd = SelinuxSidtabChildEnd.EXITED,
        signal = 0, failureReason = "diagnostic\tvalue",
        rounds = (0 until 2).map { index ->
            val before = 100L + index * 4
            SelinuxSidtabRound(before, before, before, before + 4, before + 4, before + 4, 0, 22,
                (0 until 4).map { SelinuxSidtabSample("u:r:app_zygote:s0:c${index * 4 + it}", 0, 13, 0) })
        },
    )
}
