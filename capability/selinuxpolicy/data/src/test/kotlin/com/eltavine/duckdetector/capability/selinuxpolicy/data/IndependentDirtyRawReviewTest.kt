package com.eltavine.duckdetector.capability.selinuxpolicy.data

import org.junit.Assert.*
import org.junit.Test

class IndependentDirtyRawReviewTest {
    private val base = SelinuxContextValiditySnapshot(available = true, carrierMatchesExpected = true,
        carrierContext = "u:r:app_zygote:s0:c512,c768")
    private fun response(value: Boolean, seq: Long = 1) = "${if(value) 1 else 0} ffffffff 0 ffffffff $seq 0"
    private fun baseline(s: String, t: String, c: String, p: String): String = response(
        s == "u:r:app_zygote:s0" && (p == "setcurrent" || p == "check_context" || p == "dyntransition"))
    private fun inspect(check: (String,String,String,String)->String = ::baseline,
        snapshot: SelinuxContextValiditySnapshot = base, seq: Long = 1,
        context: (String)->String = { if(it == base.carrierContext) "VALID" else "INVALID" }) =
        SelinuxDirtySepolicyRawProbe().inspect(snapshot, true, check, { _,_->1u },
            { _,_-> response(false, seq) }, context)

    @Test fun changingAdditionalRuleMustNotBeComplete() {
        var calls = 0
        val result = inspect(check = { s,t,c,p ->
            if (s == "u:r:kernel:s0" && t == "u:object_r:adb_data_file:s0") response(++calls == 1)
            else baseline(s,t,c,p)
        })
        assertEquals(2, calls)
        assertEquals(SelinuxDirtySepolicyRawState.PARTIAL, result.state)
    }
    @Test fun unrelatedIoFailureMustRetainControlledPositive() {
        val result = inspect(check = { s,t,c,p -> when(t) {
            "u:object_r:ksu_file:s0" -> response(true)
            "u:r:msd_daemon:s0" -> throw java.io.IOException("injected unavailable optional rule")
            else -> baseline(s,t,c,p)
        } })
        assertTrue("controlled KSU edge lost: ${result.state}", "untrusted_app -> ksu_file read" in result.allowedRules)
    }
    @Test fun contextCollectionMustNotDependOnAttrPayload() {
        var targetCalls = 0
        inspect(context = { context ->
            if (context == "u:r:adbroot:s0") targetCalls++
            if (context == base.carrierContext || context == "u:r:adbroot:s0") "VALID" else "INVALID"
        })
        assertTrue("No adbroot query when attr payload absent", targetCalls > 0)
    }
    @Test fun seqnoMustFitKernelUnsigned32BitField() {
        assertNull(SelinuxRawAccess.parse("0 ffffffff 0 ffffffff 4294967296 0"))
    }
    @Test fun classZeroFallbackMustHaveOwnNegativeControl() {
        val result = inspect(snapshot = base.copy(procAttrCurrentResults = listOf(
            SelinuxProcAttrCurrentResult("ADB root", "u:r:adbroot:s0", "INCONCLUSIVE", "no attr controls"))))
        assertTrue("class=0 returned a decision for every input, including invalid contexts", result.recognizedContexts.isEmpty())
    }
    @Test fun avdSeqnoOnlyIsRetainedWithoutVerdict() {
        val result = inspect(seq = 2)
        assertEquals(2L, result.avdSeqno)
        assertEquals(SelinuxDirtySepolicyRawState.COMPLETE, result.state)
        assertTrue(result.allowedRules.isEmpty() && result.apiDisagreements.isEmpty() && result.recognizedContexts.isEmpty())
    }
}
