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

package com.eltavine.duckdetector.features.selinux.data.probes

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxPolicyloadSeqnoProbeTest {

    private val probe = SelinuxPolicyloadSeqnoProbe()

    @Test
    fun `matching status policyload and access seqno is clean`() {
        val result = probe.interpret(
            status = status(sequence = 12, policyload = 9),
            access = access(seqno = 9),
        )

        assertEquals(SelinuxPolicyloadSeqnoState.CLEAN, result.state)
        assertTrue(result.available)
        assertTrue(result.probeAttempted)
        assertEquals(12L, result.statusSequence)
        assertEquals(9L, result.statusPolicyload)
        assertEquals(9L, result.accessSeqno)
        assertEquals(2, result.processClass)
    }

    @Test
    fun `nonzero sequence with zero policyload and positive access seqno is suspicious`() {
        val result = probe.interpret(
            status = status(sequence = 4, policyload = 0),
            access = access(seqno = 9),
        )

        assertEquals(SelinuxPolicyloadSeqnoState.SUSPICIOUS, result.state)
        assertTrue(result.available)
        assertEquals(0L, result.statusPolicyload)
        assertEquals(9L, result.accessSeqno)
    }

    @Test
    fun `fresh zero status page stays inconclusive instead of suspicious`() {
        val result = probe.interpret(
            status = status(sequence = 0, policyload = 0),
            access = access(seqno = 9),
        )

        assertEquals(SelinuxPolicyloadSeqnoState.INCONCLUSIVE, result.state)
        assertTrue(result.available)
        assertEquals(0L, result.statusSequence)
        assertEquals(0L, result.statusPolicyload)
        assertEquals(9L, result.accessSeqno)
    }

    @Test
    fun `odd status sequence stays inconclusive instead of suspicious`() {
        val result = probe.interpret(
            status = status(sequence = 5, policyload = 0),
            access = access(seqno = 9),
        )

        assertEquals(SelinuxPolicyloadSeqnoState.INCONCLUSIVE, result.state)
        assertTrue(result.available)
        assertEquals(5L, result.statusSequence)
        assertEquals(0L, result.statusPolicyload)
        assertEquals(9L, result.accessSeqno)
    }

    @Test
    fun `positive policyload mismatch is suspicious`() {
        val result = probe.interpret(
            status = status(sequence = 12, policyload = 7),
            access = access(seqno = 9),
        )

        assertEquals(SelinuxPolicyloadSeqnoState.SUSPICIOUS, result.state)
        assertTrue(result.available)
        assertEquals(7L, result.statusPolicyload)
        assertEquals(9L, result.accessSeqno)
    }

    private fun status(
        sequence: Long,
        policyload: Long,
    ) = SelinuxPolicyloadSeqnoProbe.SelinuxStatus(
        version = 1,
        sequence = sequence,
        enforcing = 1,
        policyload = policyload,
        denyUnknown = 0,
    )

    private fun access(
        seqno: Long,
    ) = SelinuxPolicyloadSeqnoProbe.AccessDecision(
        processClass = 2,
        seqno = seqno,
    )
}
