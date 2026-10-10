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

package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxContextValidityBridge
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxContextValiditySnapshot
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxPolicyloadSeqnoState
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxProcAttrCurrentResult
import com.eltavine.duckdetector.features.selinux.data.repository.EvidenceSource
import com.eltavine.duckdetector.features.selinux.data.repository.buildContextValidityMethod
import com.eltavine.duckdetector.features.selinux.data.repository.buildPolicyloadSeqnoMethod
import com.eltavine.duckdetector.features.selinux.data.repository.buildProcAttrCurrentMethod
import com.eltavine.duckdetector.features.selinux.domain.AppZygoteCarrierSupportState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxContextValidityReading
import com.eltavine.duckdetector.features.selinux.domain.SelinuxContextValidityVerdict
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyloadSeqnoLabels
import com.eltavine.duckdetector.features.selinux.domain.SelinuxProcAttrCurrentVerdict
import com.eltavine.duckdetector.features.selinux.domain.contextValiditySupportState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxContextValidityMethodTest {

    @Test
    fun `a clean reading is typed and keeps its text`() {
        val method = methodFor(trustedSnapshot())

        assertEquals(SelinuxOracle.CONTEXT_VALIDITY, method.oracle)
        assertEquals(SelinuxOracle.CONTEXT_VALIDITY.label, method.method)
        assertEquals(
            SelinuxContextValidityReading(SelinuxContextValidityVerdict.CLEAN, AppZygoteCarrierSupportState.AVAILABLE),
            method.contextValidity,
        )
        assertEquals(SelinuxContextValidityVerdict.CLEAN.label, method.status)
    }

    @Test
    fun `an untrusted reading flags repeatability exactly where its detail says so`() {
        val method = methodFor(trustedSnapshot().copy(ksuResultsStable = false))

        assertEquals(SelinuxContextValidityVerdict.SELF_TEST_FAILED, method.contextValidity?.verdict)
        assertEquals(true, method.contextValidity?.repeatabilityFailed)
        assertTrue(method.details.orEmpty().contains("repeatability failed"))
    }

    @Test
    fun `an unsupported reading carries the carrier state its detail names`() {
        val untrusted = methodFor(trustedSnapshot().copy(carrierMatchesExpected = false))
        val failed = methodFor(trustedSnapshot().copy(available = false))

        assertEquals(AppZygoteCarrierSupportState.UNTRUSTED, contextValiditySupportState(untrusted))
        assertTrue(untrusted.details.orEmpty().contains("Carrier state=untrusted"))
        assertEquals(AppZygoteCarrierSupportState.FAILED, contextValiditySupportState(failed))
        assertTrue(failed.details.orEmpty().contains("Carrier state=failed"))
    }

    @Test
    fun `attr current recognition requires complete controls and names only repeated hits`() {
        val method = attrMethod(controlledResults())
        assertEquals(listOf("KernelSU", "LSPosed file"), method.attrCurrentDetections)
        assertEquals(SelinuxProcAttrCurrentVerdict.CONTEXT_RECOGNIZED, method.attrCurrentVerdict)
        assertEquals("Context recognized: KernelSU, LSPosed file", method.status)
        assertEquals(false, method.isSecure)
    }

    @Test
    fun `legacy refusals successes and security exceptions cannot establish recognition`() {
        for (outcome in listOf(SelinuxProcAttrCurrentResult.OUTCOME_DETECTED_NON_EINVAL,
            SelinuxProcAttrCurrentResult.OUTCOME_SUCCESS,
            SelinuxProcAttrCurrentResult.OUTCOME_DETECTED_SECURITY_EXCEPTION)) {
            val method = attrMethod(listOf(attrResult("KernelSU", outcome)))
            assertTrue(method.attrCurrentDetections.isEmpty())
            assertEquals(SelinuxProcAttrCurrentVerdict.INCONCLUSIVE, method.attrCurrentVerdict)
            assertEquals(null, method.isSecure)
        }
    }

    @Test
    fun `failed duplicate or incomplete controls suppress recognized results`() {
        val valid = controlledResults()
        val failed = valid.first().copy(outcomeClass = SelinuxProcAttrCurrentResult.OUTCOME_PERMISSION_LIMITED)
        for (rows in listOf(listOf(failed) + valid.drop(1), valid + valid.first(), valid.dropLast(1))) {
            val method = attrMethod(rows)
            assertTrue(method.attrCurrentDetections.isEmpty())
            assertEquals(null, method.isSecure)
        }
        val limited = attrMethod(listOf(failed) + valid.drop(1))
        assertTrue(limited.permissionDenied)
        assertEquals(SelinuxProcAttrCurrentVerdict.PERMISSION_LIMITED, limited.attrCurrentVerdict)
        assertEquals("Permission limited", limited.status)
        for ((state, verdict) in listOf(
            SelinuxProcAttrCurrentResult.OUTCOME_UNSUPPORTED to SelinuxProcAttrCurrentVerdict.UNSUPPORTED,
            SelinuxProcAttrCurrentResult.OUTCOME_UNAVAILABLE to SelinuxProcAttrCurrentVerdict.UNAVAILABLE,
            SelinuxProcAttrCurrentResult.OUTCOME_INCONCLUSIVE to SelinuxProcAttrCurrentVerdict.INCONCLUSIVE,
        )) {
            val method = attrMethod(listOf(failed.copy(outcomeClass = state)))
            assertEquals(verdict, method.attrCurrentVerdict)
            assertEquals(verdict.label, method.status)
            assertFalse(method.permissionDenied)
        }
        assertEquals(SelinuxProcAttrCurrentVerdict.INCONCLUSIVE, attrMethod(valid + valid.first()).attrCurrentVerdict)
        assertEquals(SelinuxProcAttrCurrentVerdict.INCONCLUSIVE, attrMethod(valid.dropLast(1)).attrCurrentVerdict)
    }

    @Test
    fun `all tested contexts rejected is an observation and cannot exclude hiding`() {
        val rows = controlledResults().mapIndexed { index, row ->
            if (index == 0) row else row.copy(outcomeClass = SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL)
        }
        val method = attrMethod(rows)
        assertEquals(SelinuxProcAttrCurrentVerdict.NOT_RECOGNIZED, method.attrCurrentVerdict)
        assertEquals("Tested contexts not recognized", method.status)
        assertEquals(null, method.isSecure)
        assertTrue(method.details.orEmpty().contains("cannot exclude a hidden policy"))
    }

    @Test
    fun `a skipped or empty attr current probe is unsupported and keeps its reason`() {
        val skipped = buildProcAttrCurrentMethod(
            SelinuxContextValidityProbe(nativeBridge = FakeBridge(trustedSnapshot().copy(
                procAttrCurrentFailureReason = "Carrier self-check failed.",
            ))).inspectLocal(),
            EvidenceSource.DEDICATED_CARRIER,
        )
        assertEquals(SelinuxProcAttrCurrentVerdict.UNSUPPORTED, skipped.attrCurrentVerdict)
        assertTrue(skipped.details.orEmpty().contains("Carrier self-check failed."))
        val empty = attrMethod(emptyList())
        assertEquals(SelinuxProcAttrCurrentVerdict.UNSUPPORTED, empty.attrCurrentVerdict)
        assertTrue(empty.details.orEmpty().contains("returned no results"))
        assertEquals(null, empty.isSecure)
    }

    private fun controlledResults() = listOf(
        attrResult(SelinuxProcAttrCurrentResult.CONTROL_LABEL, SelinuxProcAttrCurrentResult.OUTCOME_CONTROLS_PASSED),
    ) + listOf("KernelSU", "Magisk", "LSPosed file", "file1", "file2", "domain1", "domain2", "domain3", "file3")
        .map { attrResult(it, if (it in listOf("KernelSU", "LSPosed file"))
            SelinuxProcAttrCurrentResult.OUTCOME_CONTEXT_RECOGNIZED else SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL) }

    private fun attrMethod(rows: List<SelinuxProcAttrCurrentResult>) = buildProcAttrCurrentMethod(
        SelinuxContextValidityProbe(nativeBridge = FakeBridge(trustedSnapshot().copy(
            procAttrCurrentProbeAttempted = true, procAttrCurrentResults = rows,
        ))).inspectLocal(), EvidenceSource.DEDICATED_CARRIER,
    )

    @Test
    fun `a faulted status page is an insecure finding that does not borrow a carrier failure`() {
        val result = SelinuxContextValidityProbe(
            nativeBridge = FakeBridge(
                trustedSnapshot().copy(
                    failureReason = "Context validity oracle self-test failed.",
                    policyloadSeqnoAvailable = true,
                    policyloadSeqnoProbeAttempted = true,
                    policyloadSeqnoState = SelinuxPolicyloadSeqnoState.STATUS_PAGE_FAULTED.name,
                    policyloadSeqnoNotes = listOf(
                        "Child opened and mapped /sys/fs/selinux/status, then was killed by SIGKILL on the first read of the mapping.",
                    ),
                ),
            ),
        ).inspectLocal()

        val method = buildPolicyloadSeqnoMethod(result)

        assertEquals(SelinuxOracle.POLICYLOAD_SEQNO, method.oracle)
        assertEquals(SelinuxPolicyloadSeqnoLabels.STATUS_PAGE_FAULTED, method.status)
        assertEquals(false, method.isSecure)
        assertTrue(method.details.orEmpty().contains("killed by SIGKILL"))
        assertFalse(method.details.orEmpty().contains("Failure="))
    }

    private fun attrResult(label: String, outcome: String) = SelinuxProcAttrCurrentResult(
        label = label,
        targetContext = "u:r:$label:s0",
        outcomeClass = outcome,
        rawMessage = outcome,
    )

    private fun methodFor(snapshot: SelinuxContextValiditySnapshot) =
        buildContextValidityMethod(SelinuxContextValidityProbe(nativeBridge = FakeBridge(snapshot)).inspectLocal())

    private fun trustedSnapshot() = SelinuxContextValiditySnapshot(
        available = true,
        probeAttempted = true,
        carrierContext = "u:r:app_zygote:s0:c1,c2",
        carrierMatchesExpected = true,
        oracleControlsPassed = true,
        ksuResultsStable = true,
        ksuDomainValid = false,
        ksuFileValid = false,
    )

    private class FakeBridge(
        private val snapshot: SelinuxContextValiditySnapshot,
    ) : SelinuxContextValidityBridge() {
        override fun collectLocalSnapshot(): SelinuxContextValiditySnapshot = snapshot
    }
}
