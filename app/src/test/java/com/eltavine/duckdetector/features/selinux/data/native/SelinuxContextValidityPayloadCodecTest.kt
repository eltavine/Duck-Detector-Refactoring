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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxContextValidityPayloadCodecTest {

    private val bridge = SelinuxContextValidityBridge()

    @Test
    fun `encode round trips through parser`() {
        val snapshot = SelinuxContextValiditySnapshot(
            available = true,
            probeAttempted = true,
            carrierContext = "u:r:app_zygote:s0:c1,c2",
            carrierMatchesExpected = true,
            selinuxEnabled = true,
            selinuxEnforced = true,
            pidContextMatchesCurrent = true,
            procSelfContextMatchesCurrent = true,
            dyntransitionCheckPassed = true,
            carrierControlValid = true,
            negativeControlRejected = true,
            fileControlValid = true,
            fileNegativeControlRejected = true,
            oracleControlsPassed = true,
            ksuResultsStable = true,
            queryMethod = "raw selinuxfs write",
            ksuDomainValid = true,
            ksuFileValid = false,
            bitPair = "11",
            dirtyPolicyAvailable = true,
            dirtyPolicyProbeAttempted = true,
            dirtyPolicyCarrierContext = "u:r:app_zygote:s0:c1,c2",
            dirtyPolicyCarrierMatchesExpected = true,
            dirtyPolicyControlsPassed = true,
            dirtyPolicyStable = true,
            dirtyPolicyQueryMethod = "android.os.SELinux.checkSELinuxAccess",
            dirtyPolicyAccessControlAllowed = true,
            dirtyPolicyNegativeControlRejected = true,
            dirtyPolicySystemServerExecmemAllowed = true,
            dirtyPolicyFsckSysAdminAllowed = false,
            dirtyPolicyShellSuTransitionAllowed = false,
            dirtyPolicyAdbdAdbrootBinderCallAllowed = true,
            dirtyPolicyMagiskBinderCallAllowed = true,
            dirtyPolicyKsuFileReadAllowed = false,
            dirtyPolicyLsposedFileReadAllowed = true,
            dirtyPolicyMagiskDroidspacesdTransitionAllowed = true,
            dirtyPolicySuDroidspacesdTransitionAllowed = true,
            dirtyPolicySystemServerDroidspacesdBinderCallAllowed = true,
            dirtyPolicyXposedDataFileReadAllowed = false,
            dirtyPolicyZygoteAdbDataSearchAllowed = true,
            dirtyPolicyFailureReason = "Dirty policy oracle self-test failed.",
            javaDirtyPolicyAvailable = true,
            javaDirtyPolicyProbeAttempted = true,
            javaDirtyPolicyCarrierContext = "u:r:app_zygote:s0:c1,c2",
            javaDirtyPolicyCarrierMatchesExpected = true,
            javaDirtyPolicyControlsPassed = true,
            javaDirtyPolicyStable = true,
            javaDirtyPolicyQueryMethod = "android.os.SELinux.checkSELinuxAccess",
            javaDirtyPolicyAccessControlAllowed = true,
            javaDirtyPolicyNegativeControlRejected = true,
            javaDirtyPolicyMagiskDroidspacesdTransitionAllowed = true,
            javaDirtyPolicySystemServerDroidspacesdBinderCallAllowed = true,
            policyloadSeqnoAvailable = true,
            policyloadSeqnoProbeAttempted = true,
            policyloadSeqnoState = SelinuxPolicyloadSeqnoState.SUSPICIOUS.name,
            policyloadSeqnoCarrierContext = "u:r:app_zygote:s0:c1,c2",
            policyloadSeqnoStatusSequence = 4,
            policyloadSeqnoStatusPolicyload = 0,
            policyloadSeqnoAccessSeqno = 9,
            policyloadSeqnoProcessClass = 2,
            policyloadSeqnoFailureReason = "Seqno split",
            policyloadSeqnoNotes = listOf("zygotePreloadName required"),
            dirtyPolicyNotes = listOf("system_server execmem=allowed"),
            procAttrCurrentProbeAttempted = true,
            procAttrCurrentResults = listOf(
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
            procAttrCurrentFailureReason = "Carrier self-check did not establish a trusted app_zygote context.",
            failureReason = "Carrier\ncontext unavailable",
            notes = listOf(
                "Carrier context: u:r:app_zygote:s0",
                "Query\tmethod\nraw selinuxfs write",
            ),
        )

        val parsed = bridge.parse(SelinuxContextValidityPayloadCodec.encode(snapshot))

        assertTrue(parsed.available)
        assertTrue(parsed.probeAttempted)
        assertEquals(snapshot.carrierContext, parsed.carrierContext)
        assertTrue(parsed.carrierMatchesExpected)
        assertTrue(parsed.selinuxEnabled == true)
        assertTrue(parsed.selinuxEnforced == true)
        assertTrue(parsed.pidContextMatchesCurrent == true)
        assertTrue(parsed.procSelfContextMatchesCurrent == true)
        assertTrue(parsed.dyntransitionCheckPassed == true)
        assertTrue(parsed.carrierControlValid == true)
        assertTrue(parsed.negativeControlRejected == true)
        assertTrue(parsed.fileControlValid == true)
        assertTrue(parsed.fileNegativeControlRejected == true)
        assertTrue(parsed.oracleControlsPassed)
        assertTrue(parsed.ksuResultsStable)
        assertEquals(snapshot.queryMethod, parsed.queryMethod)
        assertTrue(parsed.ksuDomainValid == true)
        assertTrue(parsed.ksuFileValid == false)
        assertEquals(snapshot.bitPair, parsed.bitPair)
        assertTrue(parsed.dirtyPolicyAvailable)
        assertTrue(parsed.dirtyPolicyProbeAttempted)
        assertEquals(snapshot.dirtyPolicyCarrierContext, parsed.dirtyPolicyCarrierContext)
        assertTrue(parsed.dirtyPolicyCarrierMatchesExpected)
        assertTrue(parsed.dirtyPolicyControlsPassed)
        assertTrue(parsed.dirtyPolicyStable)
        assertEquals(snapshot.dirtyPolicyQueryMethod, parsed.dirtyPolicyQueryMethod)
        assertEquals(snapshot.dirtyPolicyAccessControlAllowed, parsed.dirtyPolicyAccessControlAllowed)
        assertEquals(snapshot.dirtyPolicyNegativeControlRejected, parsed.dirtyPolicyNegativeControlRejected)
        assertEquals(snapshot.dirtyPolicySystemServerExecmemAllowed, parsed.dirtyPolicySystemServerExecmemAllowed)
        assertEquals(snapshot.dirtyPolicyFsckSysAdminAllowed, parsed.dirtyPolicyFsckSysAdminAllowed)
        assertEquals(snapshot.dirtyPolicyShellSuTransitionAllowed, parsed.dirtyPolicyShellSuTransitionAllowed)
        assertEquals(snapshot.dirtyPolicyAdbdAdbrootBinderCallAllowed, parsed.dirtyPolicyAdbdAdbrootBinderCallAllowed)
        assertEquals(snapshot.dirtyPolicyMagiskBinderCallAllowed, parsed.dirtyPolicyMagiskBinderCallAllowed)
        assertEquals(snapshot.dirtyPolicyKsuFileReadAllowed, parsed.dirtyPolicyKsuFileReadAllowed)
        assertEquals(snapshot.dirtyPolicyLsposedFileReadAllowed, parsed.dirtyPolicyLsposedFileReadAllowed)
        assertEquals(snapshot.dirtyPolicyMagiskDroidspacesdTransitionAllowed, parsed.dirtyPolicyMagiskDroidspacesdTransitionAllowed)
        assertEquals(snapshot.dirtyPolicySuDroidspacesdTransitionAllowed, parsed.dirtyPolicySuDroidspacesdTransitionAllowed)
        assertEquals(snapshot.dirtyPolicySystemServerDroidspacesdBinderCallAllowed, parsed.dirtyPolicySystemServerDroidspacesdBinderCallAllowed)
        assertEquals(snapshot.dirtyPolicyXposedDataFileReadAllowed, parsed.dirtyPolicyXposedDataFileReadAllowed)
        assertEquals(snapshot.dirtyPolicyZygoteAdbDataSearchAllowed, parsed.dirtyPolicyZygoteAdbDataSearchAllowed)
        assertEquals(snapshot.dirtyPolicyFailureReason, parsed.dirtyPolicyFailureReason)
        assertEquals(snapshot.dirtyPolicyNotes, parsed.dirtyPolicyNotes)
        assertTrue(parsed.javaDirtyPolicyAvailable)
        assertTrue(parsed.javaDirtyPolicyProbeAttempted)
        assertEquals(snapshot.javaDirtyPolicyMagiskDroidspacesdTransitionAllowed, parsed.javaDirtyPolicyMagiskDroidspacesdTransitionAllowed)
        assertEquals(snapshot.javaDirtyPolicySystemServerDroidspacesdBinderCallAllowed, parsed.javaDirtyPolicySystemServerDroidspacesdBinderCallAllowed)
        assertTrue(parsed.policyloadSeqnoAvailable)
        assertTrue(parsed.policyloadSeqnoProbeAttempted)
        assertEquals(snapshot.policyloadSeqnoState, parsed.policyloadSeqnoState)
        assertEquals(snapshot.policyloadSeqnoCarrierContext, parsed.policyloadSeqnoCarrierContext)
        assertEquals(snapshot.policyloadSeqnoStatusSequence, parsed.policyloadSeqnoStatusSequence)
        assertEquals(snapshot.policyloadSeqnoStatusPolicyload, parsed.policyloadSeqnoStatusPolicyload)
        assertEquals(snapshot.policyloadSeqnoAccessSeqno, parsed.policyloadSeqnoAccessSeqno)
        assertEquals(snapshot.policyloadSeqnoProcessClass, parsed.policyloadSeqnoProcessClass)
        assertEquals(snapshot.policyloadSeqnoFailureReason, parsed.policyloadSeqnoFailureReason)
        assertEquals(snapshot.policyloadSeqnoNotes, parsed.policyloadSeqnoNotes)
        assertTrue(parsed.procAttrCurrentProbeAttempted)
        assertEquals(snapshot.procAttrCurrentResults, parsed.procAttrCurrentResults)
        assertEquals(snapshot.procAttrCurrentFailureReason, parsed.procAttrCurrentFailureReason)
        assertEquals(snapshot.failureReason, parsed.failureReason)
        assertEquals(snapshot.notes, parsed.notes)
    }
}
