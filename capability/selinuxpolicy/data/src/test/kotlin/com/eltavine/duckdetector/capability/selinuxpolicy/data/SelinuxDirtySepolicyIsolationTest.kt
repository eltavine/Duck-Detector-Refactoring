package com.eltavine.duckdetector.capability.selinuxpolicy.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxDirtySepolicyIsolationTest {
    @Test fun `unstable new optional rule cannot revoke a trusted legacy KSU finding`() {
        var extraCalls = 0
        val original = SelinuxContextValiditySnapshot(
            available = true,
            carrierContext = "u:r:app_zygote:s0:c1,c2",
            carrierMatchesExpected = true,
        )
        val sampled = original.applyJavaDirtyPolicyResults(true) { source, target, _, permission ->
            when {
                source == "u:r:app_zygote:s0" && target == "u:r:isolated_app:s0" -> true
                target == "u:r:duckdetector_dirty_policy_sentinel:s0" -> false
                target == "u:object_r:ksu_file:s0" && permission == "read" -> true
                source == "u:r:kernel:s0" && target == "u:object_r:adb_data_file:s0" -> ++extraCalls == 1
                else -> false
            }
        }
        assertEquals(2, extraCalls)
        assertEquals(true, sampled.javaDirtyPolicyKsuFileReadAllowed)
        assertTrue(sampled.javaDirtyPolicyStable)
        assertTrue(sampled.javaDirtyPolicyTrusted)
        assertFalse("kernel -> adb_data_file read" in sampled.javaDirtyPolicyAdditionalRules)
    }

    @Test fun `Raw replay exception preserves all prior probe values and reports an independent error`() {
        val old = SelinuxContextValiditySnapshot(
            available = true,
            carrierContext = "u:r:app_zygote:s0:c1,c2",
            carrierMatchesExpected = true,
            dirtyPolicyKsuFileReadAllowed = true,
            javaDirtyPolicyLsposedFileReadAllowed = true,
            policyloadSeqnoState = SelinuxPolicyloadSeqnoState.SUSPICIOUS.name,
        )
        val result = collectDirtySepolicyRawSafely(old) {
            throw IllegalStateException("simulated Raw replay interruption")
        }
        assertEquals(old.copy(dirtySepolicyRaw = result.dirtySepolicyRaw), result)
        assertEquals(SelinuxDirtySepolicyRawState.UNAVAILABLE, result.dirtySepolicyRaw.state)
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.ERROR, result.dirtySepolicyRaw.compatibility.verdict)
        assertTrue(result.dirtySepolicyRaw.compatibility.reasons.single().contains("simulated Raw replay"))
    }

    @Test fun `successful Raw replay only appends its own result`() {
        val old = SelinuxContextValiditySnapshot(dirtyPolicyKsuFileReadAllowed = true)
        val raw = SelinuxDirtySepolicyRawSnapshot(state = SelinuxDirtySepolicyRawState.COMPLETE)
        assertEquals(old.copy(dirtySepolicyRaw = raw), collectDirtySepolicyRawSafely(old) { raw })
    }

    @Test fun `Raw replay without a throwable message preserves the compatibility error`() {
        val previous = SelinuxContextValiditySnapshot(dirtyPolicyKsuFileReadAllowed = true)
        val snapshot = collectDirtySepolicyRawSafely(previous) { throw IllegalStateException() }
        assertEquals(true, snapshot.dirtyPolicyKsuFileReadAllowed)
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.ERROR, snapshot.dirtySepolicyRaw.compatibility.verdict)
        assertEquals("DirtySepolicy Raw replay failed: unknown cause", snapshot.dirtySepolicyRaw.failureReason)
    }
}
