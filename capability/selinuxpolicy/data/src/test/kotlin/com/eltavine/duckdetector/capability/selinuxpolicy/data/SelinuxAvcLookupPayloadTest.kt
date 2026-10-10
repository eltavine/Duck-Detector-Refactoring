// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.capability.selinuxpolicy.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class SelinuxAvcLookupPayloadTest {
    private val observed = SelinuxAvcLookupSnapshot(
        state = SelinuxAvcLookupState.COLLECTED,
        cpu = 1, cpuRows = 8, pairs = 128, rounds = 4, writesPerBatch = 4096,
        lookupsA = 16428, lookupsB = 32825,
        batchesA = listOf(4111, 4103, 4103, 4111),
        batchesB = listOf(8199, 8214, 8202, 8210),
        medianANs = 1125, medianBNs = 1291, pairedDeltaNs = -161, childEnd = 2,
        profile = 1,
    )

    @Test fun `collected values survive nested carrier serialization`() {
        val snapshot = SelinuxContextValiditySnapshot(avcLookup = observed)
        val parsed = SelinuxContextValidityBridge().parse(SelinuxContextValidityPayloadCodec.encode(snapshot))
        assertEquals(observed, parsed.avcLookup)
        assertEquals(1.002685546875, parsed.avcLookup.rateA!!, 0.001)
    }

    @Test fun `timing only remains distinct from a successful stats measurement`() {
        val timing = observed.copy(state = SelinuxAvcLookupState.TIMING_ONLY, statsError = 13,
            rounds = 0, lookupsA = 0, lookupsB = 0, profile = 0)
        assertEquals(timing, SelinuxAvcLookupPayload.decode(SelinuxAvcLookupPayload.encode(timing)))
        assertNull(timing.rateA)
        assertNull(timing.rateB)
    }

    @Test fun `malformed count records cannot become a stable profile`() {
        val payload = SelinuxAvcLookupPayload.encode(observed)
        for (broken in listOf(
            payload.replace("SCHEMA=1", "SCHEMA=2"),
            payload.replace("ROUNDS=4", "ROUNDS=3"),
            payload.replace("CHILD_END=2", "CHILD_END=4"),
            payload.replace("LOOKUPS_A=16428", "LOOKUPS_A=-10"),
            payload.replace("CPU=1", "CPU=100"),
            payload.replace("PROFILE=1", "PROFILE=99"),
        )) {
            assertThrows(IllegalArgumentException::class.java) { SelinuxAvcLookupPayload.decode(broken) }
        }
    }

    @Test fun `legacy carrier payload has no collected AVC counters`() {
        val snapshot = SelinuxContextValidityBridge().parse("AVAILABLE=1\n")
        assertEquals(SelinuxAvcLookupState.NOT_COLLECTED, snapshot.avcLookup.state)
    }
}
