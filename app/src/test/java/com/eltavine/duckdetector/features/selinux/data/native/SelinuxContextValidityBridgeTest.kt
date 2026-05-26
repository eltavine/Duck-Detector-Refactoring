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

package com.eltavine.duckdetector.features.selinux.data.native

import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxPolicyloadSeqnoState
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxProcAttrCurrentResult
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxContextValidityBridgeTest {

    private val bridge = SelinuxContextValidityBridge()

    @Test
    fun `parse decodes context validity snapshot`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                PROBE_ATTEMPTED=1
                CARRIER_CONTEXT=u:r:app_zygote:s0:c1,c2
                CARRIER_MATCHES_EXPECTED=1
                SELINUX_ENABLED=1
                SELINUX_ENFORCED=1
                PID_CONTEXT_MATCHES_CURRENT=1
                PROC_SELF_CONTEXT_MATCHES_CURRENT=1
                DYNTRANSITION_CHECK_PASSED=1
                CARRIER_CONTROL_VALID=1
                NEGATIVE_CONTROL_REJECTED=1
                FILE_CONTROL_VALID=1
                FILE_NEGATIVE_CONTROL_REJECTED=1
                ORACLE_CONTROLS_PASSED=1
                KSU_RESULTS_STABLE=1
                QUERY_METHOD=raw selinuxfs write
                KSU_DOMAIN_VALID=1
                KSU_FILE_VALID=0
                BIT_PAIR=01/10
                DIRTY_POLICY_AVAILABLE=1
                DIRTY_POLICY_PROBE_ATTEMPTED=1
                DIRTY_POLICY_CARRIER_CONTEXT=u:r:app_zygote:s0:c1,c2
                DIRTY_POLICY_CARRIER_MATCHES_EXPECTED=1
                DIRTY_POLICY_CONTROLS_PASSED=1
                DIRTY_POLICY_STABLE=1
                DIRTY_POLICY_QUERY_METHOD=android.os.SELinux.checkSELinuxAccess
                DIRTY_POLICY_ACCESS_CONTROL_ALLOWED=1
                DIRTY_POLICY_NEGATIVE_CONTROL_REJECTED=1
                DIRTY_POLICY_SYSTEM_SERVER_EXECMEM_ALLOWED=1
                DIRTY_POLICY_FSCK_SYS_ADMIN_ALLOWED=0
                DIRTY_POLICY_SHELL_SU_TRANSITION_ALLOWED=0
                DIRTY_POLICY_ADBD_ADBROOT_BINDER_CALL_ALLOWED=1
                DIRTY_POLICY_MAGISK_BINDER_CALL_ALLOWED=1
                DIRTY_POLICY_KSU_FILE_READ_ALLOWED=0
                DIRTY_POLICY_LSPOSED_FILE_READ_ALLOWED=1
                DIRTY_POLICY_MAGISK_DROIDSPACESD_TRANSITION_ALLOWED=1
                DIRTY_POLICY_SU_DROIDSPACESD_TRANSITION_ALLOWED=1
                DIRTY_POLICY_SYSTEM_SERVER_DROIDSPACESD_BINDER_CALL_ALLOWED=1
                DIRTY_POLICY_XPOSED_DATA_FILE_READ_ALLOWED=0
                DIRTY_POLICY_ZYGOTE_ADB_DATA_SEARCH_ALLOWED=1
                DIRTY_POLICY_FAILURE_REASON=Dirty policy oracle self-test failed.
                DIRTY_POLICY_NOTE=system_server execmem=allowed
                JAVA_DIRTY_POLICY_AVAILABLE=1
                JAVA_DIRTY_POLICY_PROBE_ATTEMPTED=1
                JAVA_DIRTY_POLICY_CARRIER_CONTEXT=u:r:app_zygote:s0:c1,c2
                JAVA_DIRTY_POLICY_CARRIER_MATCHES_EXPECTED=1
                JAVA_DIRTY_POLICY_CONTROLS_PASSED=1
                JAVA_DIRTY_POLICY_STABLE=1
                JAVA_DIRTY_POLICY_QUERY_METHOD=android.os.SELinux.checkSELinuxAccess
                JAVA_DIRTY_POLICY_ACCESS_CONTROL_ALLOWED=1
                JAVA_DIRTY_POLICY_NEGATIVE_CONTROL_REJECTED=1
                JAVA_DIRTY_POLICY_LSPOSED_FILE_READ_ALLOWED=1
                JAVA_DIRTY_POLICY_MAGISK_DROIDSPACESD_TRANSITION_ALLOWED=1
                JAVA_DIRTY_POLICY_FAILURE_REASON=Java dirty policy oracle self-test failed.
                JAVA_DIRTY_POLICY_NOTE=java system_server execmem=allowed
                POLICYLOAD_SEQNO_AVAILABLE=1
                POLICYLOAD_SEQNO_PROBE_ATTEMPTED=1
                POLICYLOAD_SEQNO_STATE=SUSPICIOUS
                POLICYLOAD_SEQNO_CARRIER_CONTEXT=u:r:app_zygote:s0:c1,c2
                POLICYLOAD_SEQNO_STATUS_SEQUENCE=4
                POLICYLOAD_SEQNO_STATUS_POLICYLOAD=0
                POLICYLOAD_SEQNO_ACCESS_SEQNO=9
                POLICYLOAD_SEQNO_PROCESS_CLASS=2
                POLICYLOAD_SEQNO_FAILURE_REASON=Seqno split
                POLICYLOAD_SEQNO_NOTE=zygotePreloadName required
                PROC_ATTR_CURRENT_PROBE_ATTEMPTED=1
                PROC_ATTR_CURRENT_RESULT=KernelSU\tu:r:ksu:s0\tNORMAL_EINVAL\tErrnoException: errno=22, Invalid argument
                PROC_ATTR_CURRENT_RESULT=Magisk\tu:r:magisk:s0\tDETECTED_NON_EINVAL\tErrnoException: errno=13, Permission denied
                PROC_ATTR_CURRENT_FAILURE_REASON=Carrier self-check did not establish a trusted app_zygote context.
                FAILURE_REASON=Carrier\ncontext unavailable
                NOTE=Carrier\ncontext: u:r:app_zygote:s0
                NOTE=Query\tmethod\nraw selinuxfs write
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.probeAttempted)
        assertEquals("u:r:app_zygote:s0:c1,c2", snapshot.carrierContext)
        assertTrue(snapshot.carrierMatchesExpected)
        assertTrue(snapshot.selinuxEnabled == true)
        assertTrue(snapshot.selinuxEnforced == true)
        assertTrue(snapshot.pidContextMatchesCurrent == true)
        assertTrue(snapshot.procSelfContextMatchesCurrent == true)
        assertTrue(snapshot.dyntransitionCheckPassed == true)
        assertTrue(snapshot.carrierControlValid == true)
        assertTrue(snapshot.negativeControlRejected == true)
        assertTrue(snapshot.fileControlValid == true)
        assertTrue(snapshot.fileNegativeControlRejected == true)
        assertTrue(snapshot.oracleControlsPassed)
        assertTrue(snapshot.ksuResultsStable)
        assertEquals("raw selinuxfs write", snapshot.queryMethod)
        assertEquals(true, snapshot.ksuDomainValid)
        assertEquals(false, snapshot.ksuFileValid)
        assertEquals("01/10", snapshot.bitPair)
        assertTrue(snapshot.dirtyPolicyAvailable)
        assertTrue(snapshot.dirtyPolicyProbeAttempted)
        assertEquals("u:r:app_zygote:s0:c1,c2", snapshot.dirtyPolicyCarrierContext)
        assertTrue(snapshot.dirtyPolicyCarrierMatchesExpected)
        assertTrue(snapshot.dirtyPolicyControlsPassed)
        assertTrue(snapshot.dirtyPolicyStable)
        assertEquals("android.os.SELinux.checkSELinuxAccess", snapshot.dirtyPolicyQueryMethod)
        assertEquals(true, snapshot.dirtyPolicyAccessControlAllowed)
        assertEquals(true, snapshot.dirtyPolicyNegativeControlRejected)
        assertEquals(true, snapshot.dirtyPolicySystemServerExecmemAllowed)
        assertEquals(false, snapshot.dirtyPolicyFsckSysAdminAllowed)
        assertEquals(false, snapshot.dirtyPolicyShellSuTransitionAllowed)
        assertEquals(true, snapshot.dirtyPolicyAdbdAdbrootBinderCallAllowed)
        assertEquals(true, snapshot.dirtyPolicyMagiskBinderCallAllowed)
        assertEquals(false, snapshot.dirtyPolicyKsuFileReadAllowed)
        assertEquals(true, snapshot.dirtyPolicyLsposedFileReadAllowed)
        assertEquals(true, snapshot.dirtyPolicyMagiskDroidspacesdTransitionAllowed)
        assertEquals(true, snapshot.dirtyPolicySuDroidspacesdTransitionAllowed)
        assertEquals(true, snapshot.dirtyPolicySystemServerDroidspacesdBinderCallAllowed)
        assertEquals(false, snapshot.dirtyPolicyXposedDataFileReadAllowed)
        assertEquals(true, snapshot.dirtyPolicyZygoteAdbDataSearchAllowed)
        assertEquals("Dirty policy oracle self-test failed.", snapshot.dirtyPolicyFailureReason)
        assertEquals(listOf("system_server execmem=allowed"), snapshot.dirtyPolicyNotes)
        assertTrue(snapshot.javaDirtyPolicyAvailable)
        assertTrue(snapshot.javaDirtyPolicyProbeAttempted)
        assertEquals("u:r:app_zygote:s0:c1,c2", snapshot.javaDirtyPolicyCarrierContext)
        assertTrue(snapshot.javaDirtyPolicyCarrierMatchesExpected)
        assertTrue(snapshot.javaDirtyPolicyControlsPassed)
        assertTrue(snapshot.javaDirtyPolicyStable)
        assertEquals("android.os.SELinux.checkSELinuxAccess", snapshot.javaDirtyPolicyQueryMethod)
        assertEquals(true, snapshot.javaDirtyPolicyAccessControlAllowed)
        assertEquals(true, snapshot.javaDirtyPolicyNegativeControlRejected)
        assertEquals(true, snapshot.javaDirtyPolicyLsposedFileReadAllowed)
        assertEquals(true, snapshot.javaDirtyPolicyMagiskDroidspacesdTransitionAllowed)
        assertEquals("Java dirty policy oracle self-test failed.", snapshot.javaDirtyPolicyFailureReason)
        assertEquals(listOf("java system_server execmem=allowed"), snapshot.javaDirtyPolicyNotes)
        assertTrue(snapshot.policyloadSeqnoAvailable)
        assertTrue(snapshot.policyloadSeqnoProbeAttempted)
        assertEquals(SelinuxPolicyloadSeqnoState.SUSPICIOUS.name, snapshot.policyloadSeqnoState)
        assertEquals("u:r:app_zygote:s0:c1,c2", snapshot.policyloadSeqnoCarrierContext)
        assertEquals(4L, snapshot.policyloadSeqnoStatusSequence)
        assertEquals(0L, snapshot.policyloadSeqnoStatusPolicyload)
        assertEquals(9L, snapshot.policyloadSeqnoAccessSeqno)
        assertEquals(2, snapshot.policyloadSeqnoProcessClass)
        assertEquals("Seqno split", snapshot.policyloadSeqnoFailureReason)
        assertEquals(listOf("zygotePreloadName required"), snapshot.policyloadSeqnoNotes)
        assertEquals(true, snapshot.procAttrCurrentProbeAttempted)
        assertEquals(
            listOf(
                SelinuxProcAttrCurrentResult(
                    label = "KernelSU",
                    targetContext = "u:r:ksu:s0",
                    outcomeClass = SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL,
                    rawMessage = "ErrnoException: errno=22, Invalid argument",
                ),
                SelinuxProcAttrCurrentResult(
                    label = "Magisk",
                    targetContext = "u:r:magisk:s0",
                    outcomeClass = SelinuxProcAttrCurrentResult.OUTCOME_DETECTED_NON_EINVAL,
                    rawMessage = "ErrnoException: errno=13, Permission denied",
                ),
            ),
            snapshot.procAttrCurrentResults,
        )
        assertEquals(
            "Carrier self-check did not establish a trusted app_zygote context.",
            snapshot.procAttrCurrentFailureReason,
        )
        assertEquals("Carrier\ncontext unavailable", snapshot.failureReason)
        assertEquals(
            listOf(
                "Carrier\ncontext: u:r:app_zygote:s0",
                "Query\tmethod\nraw selinuxfs write",
            ),
            snapshot.notes,
        )
    }

    @Test
    fun `parse keeps preload style dirty policy and attr current results`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                PROBE_ATTEMPTED=1
                CARRIER_CONTEXT=u:r:app_zygote:s0:c1,c2
                CARRIER_MATCHES_EXPECTED=1
                DIRTY_POLICY_AVAILABLE=1
                DIRTY_POLICY_PROBE_ATTEMPTED=1
                DIRTY_POLICY_CARRIER_CONTEXT=u:r:app_zygote:s0:c1,c2
                DIRTY_POLICY_CARRIER_MATCHES_EXPECTED=1
                DIRTY_POLICY_CONTROLS_PASSED=1
                DIRTY_POLICY_STABLE=1
                DIRTY_POLICY_QUERY_METHOD=android.os.SELinux.checkSELinuxAccess
                DIRTY_POLICY_ACCESS_CONTROL_ALLOWED=1
                DIRTY_POLICY_NEGATIVE_CONTROL_REJECTED=1
                DIRTY_POLICY_SYSTEM_SERVER_EXECMEM_ALLOWED=1
                DIRTY_POLICY_LSPOSED_FILE_READ_ALLOWED=1
                JAVA_DIRTY_POLICY_AVAILABLE=1
                JAVA_DIRTY_POLICY_PROBE_ATTEMPTED=1
                JAVA_DIRTY_POLICY_CARRIER_CONTEXT=u:r:app_zygote:s0:c1,c2
                JAVA_DIRTY_POLICY_CARRIER_MATCHES_EXPECTED=1
                JAVA_DIRTY_POLICY_CONTROLS_PASSED=1
                JAVA_DIRTY_POLICY_STABLE=1
                JAVA_DIRTY_POLICY_QUERY_METHOD=android.os.SELinux.checkSELinuxAccess
                JAVA_DIRTY_POLICY_ACCESS_CONTROL_ALLOWED=1
                JAVA_DIRTY_POLICY_NEGATIVE_CONTROL_REJECTED=1
                JAVA_DIRTY_POLICY_LSPOSED_FILE_READ_ALLOWED=1
                PROC_ATTR_CURRENT_PROBE_ATTEMPTED=1
                PROC_ATTR_CURRENT_RESULT=LSPosed file\tu:r:lsposed_file:s0\tDETECTED_NON_EINVAL\tErrnoException: errno=1, Operation not permitted
            """.trimIndent(),
        )

        assertTrue(snapshot.dirtyPolicyAvailable)
        assertTrue(snapshot.dirtyPolicyProbeAttempted)
        assertEquals("android.os.SELinux.checkSELinuxAccess", snapshot.dirtyPolicyQueryMethod)
        assertEquals(true, snapshot.dirtyPolicySystemServerExecmemAllowed)
        assertEquals(true, snapshot.dirtyPolicyLsposedFileReadAllowed)
        assertTrue(snapshot.javaDirtyPolicyAvailable)
        assertTrue(snapshot.javaDirtyPolicyProbeAttempted)
        assertEquals(true, snapshot.javaDirtyPolicyLsposedFileReadAllowed)
        assertTrue(snapshot.procAttrCurrentProbeAttempted)
        assertEquals(1, snapshot.procAttrCurrentResults.size)
        assertEquals("LSPosed file", snapshot.procAttrCurrentResults.single().label)
    }

    @Test
    fun `local snapshot path does not consume preloaded carrier payload`() {
        SelinuxContextValidityBridge.clearPreloadedRawDataForTests()
        SelinuxContextValidityBridge.setPreloadedRawData(
            """
                AVAILABLE=1
                PROBE_ATTEMPTED=1
                CARRIER_CONTEXT=u:r:app_zygote:s0:c1,c2
                CARRIER_MATCHES_EXPECTED=1
            """.trimIndent(),
        )

        val snapshot = bridge.collectLocalSnapshot()
        val raw = SelinuxContextValidityBridge.consumePreloadedRawDataForCarrier()

        assertFalse(snapshot.available)
        assertEquals("u:r:app_zygote:s0:c1,c2", bridge.parse(raw.orEmpty()).carrierContext)
    }
}
