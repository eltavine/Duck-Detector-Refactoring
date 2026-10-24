package com.eltavine.duckdetector.capability.selinuxpolicy.data

import android.system.ErrnoException
import android.system.OsConstants
import org.junit.Assert.*
import org.junit.Test

class SelinuxDirtySepolicyCompatibilityIntegrationTest {
    private val targets = listOf("u:r:ksu:s0", "u:object_r:ksu_file:s0", "u:r:magisk:s0",
        "u:object_r:magisk_file:s0", "u:object_r:lsposed_file:s0", "u:r:droidspacesd:s0",
        "u:r:msd_app:s0", "u:r:msd_daemon:s0", "u:object_r:xposed_data:s0",
        "u:r:adbroot:s0", "u:object_r:xposed_file:s0")
    private val carrier = SelinuxContextValiditySnapshot(available = true,
        carrierMatchesExpected = true, carrierContext = "u:r:app_zygote:s0:c512,c768",
        selinuxEnabled = true, selinuxEnforced = true,
        pidContextMatchesCurrent = true, procSelfContextMatchesCurrent = true,
        procAttrCurrentResults = listOf(SelinuxProcAttrCurrentResult("Controls", "", "CONTROLS_PASSED", "complete")) +
            targets.map { SelinuxProcAttrCurrentResult(it, it, "NORMAL_EINVAL", "two controlled rounds") })
    private fun response(allowed: Boolean) = "${if(allowed) 1 else 0} ffffffff 0 ffffffff 1 0"
    private fun inspect(
        adbrootState: String,
        adbrootClassZero: String = "EINVAL",
        attrRecognized: Boolean = false,
    ): SelinuxDirtySepolicyRawSnapshot = SelinuxDirtySepolicyRawProbe().inspect(
        carrier.copy(procAttrCurrentResults = carrier.procAttrCurrentResults.map {
            if (attrRecognized && it.targetContext == "u:r:adbroot:s0") {
                it.copy(outcomeClass = SelinuxProcAttrCurrentResult.OUTCOME_CONTEXT_RECOGNIZED)
            } else it
        }), true,
        query = { s,_,_,p -> response(s == "u:r:app_zygote:s0" && p in setOf("setcurrent", "check_context", "dyntransition")) },
        permissionMask = { _,_ -> 1u },
        queryClassZero = { s,_ ->
            when {
                s == carrier.carrierContext || s == "u:r:untrusted_app:s0" -> response(false)
                s == "u:r:adbroot:s0" && adbrootClassZero == "VALID" -> response(false)
                s == "u:r:adbroot:s0" && adbrootClassZero == "EACCES" ->
                    throw SelinuxRawAccess.TransactionFailure("write", 13, null,
                        java.io.IOException("injected EACCES"))
                s == "u:r:adbroot:s0" && adbrootClassZero == "MALFORMED" -> "0 ffffffff 0 0"
                else -> throw ErrnoException("write", OsConstants.EINVAL)
            }
        },
        checkContextNode = { when(it) {
            carrier.carrierContext -> "VALID"
            "u:r:adbroot:s0" -> adbrootState
            else -> "INVALID"
        } },
        statusHeader = SelinuxStatusHeader(1,0,1,0,1), kernelRelease = "5.15.148-android")

    @Test fun cleanControlledBaselineIsCompatible() {
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.OK, inspect("INVALID").compatibility.verdict)
    }
    @Test fun upstreamContextIoErrorCannotBecomeCompatibilityOk() {
        val raw = inspect("UNAVAILABLE:open errno=13")
        val observation = raw.contextChecks.single { it.context == "u:r:adbroot:s0" }
        assertEquals("UNAVAILABLE:open errno=13", observation.contextNode)
        assertEquals("INVALID", observation.verdict)
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.ERROR, raw.compatibility.verdict)
    }

    @Test fun upstreamClassZeroIoErrorCannotBeRecoveredByAttrNegative() {
        val raw = inspect("INVALID", adbrootClassZero = "EACCES")
        val observation = raw.contextChecks.single { it.context == "u:r:adbroot:s0" }
        assertEquals("INVALID", observation.contextNode)
        assertEquals("UNAVAILABLE", observation.accessNode)
        assertEquals("INVALID", observation.verdict)
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.ERROR, raw.compatibility.verdict)
    }

    @Test fun upstreamClassZeroMalformedResponseCannotBecomeCompatibleOk() {
        val raw = inspect("INVALID", adbrootClassZero = "MALFORMED")
        assertEquals("INVALID_ACCESS_RESULT", raw.contextChecks.single {
            it.context == "u:r:adbroot:s0"
        }.accessNode)
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.ERROR, raw.compatibility.verdict)
    }

    @Test fun upstreamContextIoErrorMustNotSuppressIndependentClassZeroPositive() {
        val raw = inspect("UNAVAILABLE:open errno=13", adbrootClassZero = "VALID")
        val observation = raw.contextChecks.single { it.context == "u:r:adbroot:s0" }
        assertEquals(SelinuxRawContextSource.ACCESS_CLASS_ZERO, observation.verifiedBy)
        assertTrue("u:r:adbroot:s0" in raw.recognizedContexts)
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.ERROR, raw.compatibility.verdict)
    }

    @Test fun upstreamContextIoErrorMustNotSuppressIndependentAttrPositive() {
        val raw = inspect("UNAVAILABLE:open errno=13", attrRecognized = true)
        val observation = raw.contextChecks.single { it.context == "u:r:adbroot:s0" }
        assertEquals(SelinuxRawContextSource.ATTR_CURRENT, observation.verifiedBy)
        assertTrue("u:r:adbroot:s0" in raw.recognizedContexts)
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.ERROR, raw.compatibility.verdict)
    }
}
