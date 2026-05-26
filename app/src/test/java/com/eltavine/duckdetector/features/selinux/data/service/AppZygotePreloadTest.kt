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

package com.eltavine.duckdetector.features.selinux.data.service

import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValiditySnapshot
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxPolicyloadSeqnoResult
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxPolicyloadSeqnoState
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxProcAttrCurrentResult
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValidityBridge
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppZygotePreloadTest {

    @Test
    fun `fallback payload stays parseable`() {
        val preload = AppZygotePreload()
        val method = AppZygotePreload::class.java.getDeclaredMethod(
            "fallbackPayload",
            String::class.java,
        )
        method.isAccessible = true

        val payload = method.invoke(preload, "boom\n\"quoted\"") as String
        val snapshot = SelinuxContextValidityBridge().parse(payload)

        assertFalse(snapshot.available)
        assertEquals("boom\n\"quoted\"", snapshot.failureReason)
        assertFalse(snapshot.dirtyPolicyAvailable)
        assertEquals("android.os.SELinux.checkSELinuxAccess", snapshot.dirtyPolicyQueryMethod)
        assertEquals("boom\n\"quoted\"", snapshot.dirtyPolicyFailureReason)
        assertEquals(
            listOf("Kotlin preload fallback produced a parseable SELinux snapshot."),
            snapshot.dirtyPolicyNotes,
        )
        assertEquals(
            listOf("Kotlin preload fallback produced a parseable SELinux snapshot."),
            snapshot.notes,
        )
    }

    @Test
    fun `augment preload snapshot restores DirtySepolicy style attr and rule probes`() {
        val snapshot = AppZygotePreload.augmentPreloadSnapshot(
            baseSnapshot = SelinuxContextValiditySnapshot(
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
                oracleControlsPassed = false,
                ksuResultsStable = false,
                failureReason = "Context validity oracle self-test failed.",
            ),
            currentUid = 10000,
            appUid = 10000,
            isUserBuild = true,
            inspectProcAttrCurrent = {
                listOf(
                    SelinuxProcAttrCurrentResult(
                        label = "Magisk file",
                        targetContext = "u:r:magisk_file:s0",
                        outcomeClass = SelinuxProcAttrCurrentResult.OUTCOME_DETECTED_NON_EINVAL,
                        rawMessage = "ErrnoException: errno=1, Operation not permitted",
                    ),
                )
            },
            inspectPolicyloadSeqno = {
                SelinuxPolicyloadSeqnoResult(
                    state = SelinuxPolicyloadSeqnoState.SUSPICIOUS,
                    available = true,
                    probeAttempted = true,
                    statusSequence = 4,
                    statusPolicyload = 0,
                    accessSeqno = 9,
                    processClass = 2,
                )
            },
            checkAccess = { source, target, targetClass, permission ->
                when {
                    source == "u:r:app_zygote:s0" && target == "u:r:isolated_app:s0" &&
                        targetClass == "process" && permission == "dyntransition" -> true

                    source == "u:r:untrusted_app:s0" && target == "u:r:duckdetector_dirty_policy_sentinel:s0" &&
                        targetClass == "binder" && permission == "call" -> false

                    source == "u:r:system_server:s0" && target == "u:r:system_server:s0" &&
                        targetClass == "process" && permission == "execmem" -> true

                    source == "u:r:untrusted_app:s0" && target == "u:object_r:lsposed_file:s0" &&
                        targetClass == "file" && permission == "read" -> true

                    source == "u:r:magisk:s0" && target == "u:r:droidspacesd:s0" &&
                        targetClass == "process" && permission == "dyntransition" -> true

                    source == "u:r:su:s0" && target == "u:r:droidspacesd:s0" &&
                        targetClass == "process" && permission == "dyntransition" -> true

                    source == "u:r:system_server:s0" && target == "u:r:droidspacesd:s0" &&
                        targetClass == "binder" && permission == "call" -> true

                    else -> false
                }
            },
        )

        assertTrue(snapshot.procAttrCurrentProbeAttempted)
        assertEquals(1, snapshot.procAttrCurrentResults.size)
        assertTrue(snapshot.javaDirtyPolicyAvailable)
        assertTrue(snapshot.javaDirtyPolicyProbeAttempted)
        assertTrue(snapshot.javaDirtyPolicyControlsPassed)
        assertTrue(snapshot.javaDirtyPolicyStable)
        assertTrue(snapshot.policyloadSeqnoAvailable)
        assertTrue(snapshot.policyloadSeqnoProbeAttempted)
        assertEquals(SelinuxPolicyloadSeqnoState.SUSPICIOUS.name, snapshot.policyloadSeqnoState)
        assertEquals(0L, snapshot.policyloadSeqnoStatusPolicyload)
        assertEquals(9L, snapshot.policyloadSeqnoAccessSeqno)
        assertEquals(true, snapshot.javaDirtyPolicySystemServerExecmemAllowed)
        assertEquals(true, snapshot.javaDirtyPolicyLsposedFileReadAllowed)
        assertEquals(true, snapshot.javaDirtyPolicyMagiskDroidspacesdTransitionAllowed)
        assertEquals(true, snapshot.javaDirtyPolicySuDroidspacesdTransitionAllowed)
        assertEquals(true, snapshot.javaDirtyPolicySystemServerDroidspacesdBinderCallAllowed)
        assertEquals(true, snapshot.javaDirtyPolicyNegativeControlRejected)
        assertEquals("android.os.SELinux.checkSELinuxAccess", snapshot.javaDirtyPolicyQueryMethod)
    }

    @Test
    fun `augment preload snapshot skips attr writes when carrier gate fails`() {
        var inspectCalls = 0
        var seqnoCalls = 0

        val snapshot = AppZygotePreload.augmentPreloadSnapshot(
            baseSnapshot = SelinuxContextValiditySnapshot(
                available = true,
                probeAttempted = true,
                carrierContext = "u:r:app_zygote:s0:c1,c2",
                carrierMatchesExpected = true,
                selinuxEnabled = true,
                selinuxEnforced = true,
                pidContextMatchesCurrent = false,
                procSelfContextMatchesCurrent = true,
                dyntransitionCheckPassed = true,
            ),
            currentUid = 10000,
            appUid = 10000,
            isUserBuild = true,
            inspectProcAttrCurrent = {
                inspectCalls += 1
                listOf(
                    SelinuxProcAttrCurrentResult(
                        label = "KernelSU",
                        targetContext = "u:r:ksu:s0",
                        outcomeClass = SelinuxProcAttrCurrentResult.OUTCOME_DETECTED_NON_EINVAL,
                        rawMessage = "should not run",
                    ),
                )
            },
            inspectPolicyloadSeqno = {
                seqnoCalls += 1
                SelinuxPolicyloadSeqnoResult(
                    state = SelinuxPolicyloadSeqnoState.SUSPICIOUS,
                    available = true,
                    probeAttempted = true,
                )
            },
            checkAccess = { _, _, _, _ -> null },
        )

        assertEquals(0, inspectCalls)
        assertEquals(0, seqnoCalls)
        assertFalse(snapshot.procAttrCurrentProbeAttempted)
        assertFalse(snapshot.policyloadSeqnoProbeAttempted)
        assertEquals(SelinuxPolicyloadSeqnoState.UNAVAILABLE.name, snapshot.policyloadSeqnoState)
        assertTrue(snapshot.procAttrCurrentResults.isEmpty())
        assertEquals(
            "Carrier pid context did not match the current process context.",
            snapshot.procAttrCurrentFailureReason,
        )
    }

    @Test
    fun `java carrier snapshot can recover preload gate when native base snapshot fails`() {
        val merged = AppZygotePreload.mergeCarrierSelfCheckSnapshot(
            nativeSnapshot = SelinuxContextValiditySnapshot(
                available = false,
                failureReason = "selinux native path unavailable",
            ),
            javaCarrierSnapshot = SelinuxContextValiditySnapshot(
                available = true,
                carrierContext = "u:r:app_zygote:s0:c1,c2",
                carrierMatchesExpected = true,
                selinuxEnabled = true,
                selinuxEnforced = true,
                pidContextMatchesCurrent = true,
                procSelfContextMatchesCurrent = true,
                dyntransitionCheckPassed = true,
            ),
        )

        assertTrue(merged.available)
        assertTrue(merged.probeAttempted)
        assertEquals("u:r:app_zygote:s0:c1,c2", merged.carrierContext)
        assertEquals(true, merged.carrierMatchesExpected)
        assertEquals(true, merged.selinuxEnabled)
        assertEquals(true, merged.selinuxEnforced)
        assertEquals(true, merged.pidContextMatchesCurrent)
        assertEquals(true, merged.procSelfContextMatchesCurrent)
        assertEquals(true, merged.dyntransitionCheckPassed)
        assertEquals("selinux native path unavailable", merged.failureReason)
    }

    @Test
    fun `java carrier snapshot preserves native dedicated oracle verdict`() {
        val merged = AppZygotePreload.mergeCarrierSelfCheckSnapshot(
            nativeSnapshot = SelinuxContextValiditySnapshot(
                available = true,
                probeAttempted = true,
                carrierContext = "u:r:app_zygote:s0:c9,c10",
                carrierMatchesExpected = true,
                carrierControlValid = true,
                negativeControlRejected = true,
                fileControlValid = true,
                fileNegativeControlRejected = true,
                oracleControlsPassed = true,
                ksuResultsStable = true,
                queryMethod = "raw selinuxfs write",
                ksuDomainValid = true,
                ksuFileValid = true,
                bitPair = "11",
            ),
            javaCarrierSnapshot = SelinuxContextValiditySnapshot(
                available = true,
                carrierContext = "u:r:app_zygote:s0:c1,c2",
                carrierMatchesExpected = true,
                selinuxEnabled = true,
                selinuxEnforced = true,
                pidContextMatchesCurrent = true,
                procSelfContextMatchesCurrent = true,
                dyntransitionCheckPassed = true,
            ),
        )

        assertTrue(merged.available)
        assertTrue(merged.probeAttempted)
        assertEquals("u:r:app_zygote:s0:c1,c2", merged.carrierContext)
        assertEquals(true, merged.carrierMatchesExpected)
        assertEquals(true, merged.selinuxEnabled)
        assertEquals(true, merged.selinuxEnforced)
        assertEquals(true, merged.pidContextMatchesCurrent)
        assertEquals(true, merged.procSelfContextMatchesCurrent)
        assertEquals(true, merged.dyntransitionCheckPassed)
        assertEquals(true, merged.oracleControlsPassed)
        assertEquals(true, merged.ksuResultsStable)
        assertEquals("raw selinuxfs write", merged.queryMethod)
        assertEquals(true, merged.ksuDomainValid)
        assertEquals(true, merged.ksuFileValid)
        assertEquals("11", merged.bitPair)
    }
}
