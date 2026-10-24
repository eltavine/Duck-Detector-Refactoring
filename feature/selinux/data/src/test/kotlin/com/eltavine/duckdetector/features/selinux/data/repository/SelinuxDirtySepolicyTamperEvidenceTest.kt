package com.eltavine.duckdetector.features.selinux.data.repository

import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxContextValiditySnapshot
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxDirtySepolicyRawSnapshot
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxDirtySepolicyRawState
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxRawAccessObservation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxDirtySepolicyTamperEvidenceTest {
    private val edge = "u:r:untrusted_app:s0 -> u:object_r:ksu_file:s0:file read"

    private fun samples(first: Boolean, second: Boolean, firstEpoch: Long = 1, secondEpoch: Long = 1,
        flags: String = "0"): List<SelinuxRawAccessObservation> = listOf(
        SelinuxRawAccessObservation(edge, if (first) "ALLOWED" else "DENIED",
            "${if (first) 1 else 0} ffffffff 0 ffffffff $firstEpoch $flags"),
        SelinuxRawAccessObservation(edge, if (second) "ALLOWED" else "DENIED",
            "${if (second) 1 else 0} ffffffff 0 ffffffff $secondEpoch $flags"),
    )

    private fun result(raw: SelinuxDirtySepolicyRawSnapshot) =
        buildDirtyPolicyAccessProtocolMethod(SelinuxContextValiditySnapshot(dirtySepolicyRaw = raw))

    @Test fun `controlled Raw and Java disagreement is danger even without an allowed rule`() {
        val hit = result(SelinuxDirtySepolicyRawSnapshot(
            state = SelinuxDirtySepolicyRawState.COMPLETE,
            controlsPassed = true,
            stable = true,
            apiDisagreements = listOf("untrusted_app -> ksu_file read"),
        ))
        assertEquals(false, hit.isSecure)
        assertEquals(true, hit.dirtySepolicyDanger)
        assertEquals("Raw/API disagreement", hit.status)
        assertTrue(hit.details.orEmpty().contains("Raw vs Java disagreement"))
    }

    @Test fun `same policy epoch contradictory repeated access replies are danger`() {
        val hit = result(SelinuxDirtySepolicyRawSnapshot(
            state = SelinuxDirtySepolicyRawState.PARTIAL,
            controlsPassed = true,
            stable = false,
            observations = samples(false, true),
        ))
        assertEquals(false, hit.isSecure)
        assertEquals(true, hit.dirtySepolicyDanger)
        assertEquals("Repeated access disagreement", hit.status)
        assertTrue(hit.details.orEmpty().contains("Same-epoch repeated access disagreement=$edge"))
    }

    @Test fun `different epochs and permissive flags do not imply a contradictory hook`() {
        for (pair in listOf(samples(false, true, 1, 2), samples(false, true, flags = "1"),
            samples(false, false))) {
            val hit = result(SelinuxDirtySepolicyRawSnapshot(
                state = SelinuxDirtySepolicyRawState.PARTIAL,
                controlsPassed = true,
                observations = pair,
            ))
            assertNull(hit.isSecure)
            assertEquals(false, hit.dirtySepolicyDanger)
            assertEquals("Partially collected", hit.status)
        }
    }

    @Test fun `untrusted Raw and Java comparison does not create a positive`() {
        val hit = result(SelinuxDirtySepolicyRawSnapshot(
            state = SelinuxDirtySepolicyRawState.UNTRUSTED,
            controlsPassed = false,
            apiDisagreements = listOf("untrusted_app -> ksu_file read"),
            observations = samples(false, true),
        ))
        assertNull(hit.isSecure)
        assertEquals(false, hit.dirtySepolicyDanger)
        assertEquals("Untrusted access controls", hit.status)
    }

    @Test fun `malformed response retains a danger even if controls were not trustworthy`() {
        val hit = result(SelinuxDirtySepolicyRawSnapshot(
            state = SelinuxDirtySepolicyRawState.INVALID_ACCESS_RESULT,
            controlsPassed = false,
            rawResponse = "malformed",
        ))
        assertEquals(false, hit.isSecure)
        assertEquals(true, hit.dirtySepolicyDanger)
        assertEquals("Invalid access result", hit.status)
    }
}
