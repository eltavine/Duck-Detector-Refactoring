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

package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.selinux.domain.*
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxSidtabPresentationTest {
    @Test fun `finding stays warning in headline row and export`() {
        val model = SelinuxCardModelMapper().map(report(reading(true)))
        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals("Enforcing with SID-table query discrepancy", model.verdict)
        val row = model.methodRows.single()
        assertEquals(DetectorStatus.warning(), row.status)
        assertTrue(row.detail!!.contains("does not identify KernelSU or prove root"))
        assertTrue(row.detail.contains("retained measurement"))
        assertTrue(row.detail.contains("malformed attr/current errno=22"))
        assertTrue(model.summary.contains("hidden policy reloads cannot be excluded"))
        assertTrue(!model.summary.contains("internally consistent"))
        assertTrue(model.impactItems.any { it.status == DetectorStatus.warning() && it.text.contains("SID-table") })
        assertEquals(model.verdict, model.toDetectorReport().verdict)
    }

    @Test fun `negative and missing evidence have informational rows`() {
        listOf(reading(false), reading(false).copy(collection = SelinuxSidtabCollection.NOT_COLLECTED, attempted = false),
            reading(false).copy(collection = SelinuxSidtabCollection.PERMISSION_LIMITED),
        ).forEach {
            val row = SelinuxCardModelMapper().map(report(it)).methodRows.single()
            assertEquals(DetectorStatus.info(InfoKind.SUPPORT), row.status)
            if (!it.attempted) assertTrue(row.detail!!.contains("no measurement was retained"))
        }
    }

    @Test fun `only a discrepancy reaches the summary and impact list`() {
        listOf(
            reading(false),
            reading(false).copy(collection = SelinuxSidtabCollection.NOT_COLLECTED, attempted = false),
            reading(false).copy(collection = SelinuxSidtabCollection.PERMISSION_LIMITED),
            reading(true).copy(collection = SelinuxSidtabCollection.INCONCLUSIVE),
        ).forEach {
            val model = SelinuxCardModelMapper().map(report(it))
            assertEquals(DetectorStatus.allClear(), model.status)
            assertEquals("Enforcing", model.verdict)
            assertEquals("SELinux is enforcing and the visible policy surface looks internally consistent.", model.summary)
            assertTrue(model.impactItems.none { item -> item.text.contains("SID-table") })
        }
    }

    @Test fun `a trusted dirty policy hit and an untrusted carrier keep the headline`() {
        val dirty = SelinuxCardModelMapper().map(report(reading(true), trustedDirtyPolicyHit()))
        assertEquals(DetectorStatus.warning(), dirty.status)
        assertEquals("Enforcing with dirty sepolicy rule", dirty.verdict)
        val dirtyAt = dirty.summary.indexOf("DirtySepolicy")
        assertTrue(dirtyAt >= 0 && dirtyAt < dirty.summary.indexOf("Two bounded rounds"))

        val untrusted = SelinuxCardModelMapper().map(report(reading(true), carrier(AppZygoteCarrierSupportState.UNTRUSTED)))
        assertEquals(DetectorStatus.warning(), untrusted.status)
        assertEquals("Enforcing with untrusted app_zygote carrier", untrusted.verdict)
    }

    @Test fun `reduced carrier coverage does not hide the discrepancy`() {
        val model = SelinuxCardModelMapper().map(report(reading(true), carrier(AppZygoteCarrierSupportState.FAILED)))
        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals("Enforcing with SID-table query discrepancy", model.verdict)
    }

    private fun report(reading: SelinuxSidtabReading, vararg others: SelinuxCheckResult) = SelinuxReport(
        stage = SelinuxStage.READY, mode = SelinuxMode.ENFORCING, resolvedStatusLabel = "Enforcing",
        filesystemMounted = true, paradoxDetected = false,
        methods = others.toList() + SelinuxCheckResult(SelinuxOracle.SIDTAB_CONSISTENCY.label, reading.verdict.label, null, false,
            oracle = SelinuxOracle.SIDTAB_CONSISTENCY, sidtab = reading),
        processContext = null, contextType = null, policyAnalysis = null, auditIntegrity = null,
        androidVersion = "15", apiLevel = 35,
    )

    private fun trustedDirtyPolicyHit() = SelinuxCheckResult(
        method = "Dirty sepolicy rule: system_server execmem", status = "Allowed", isSecure = false,
        permissionDenied = false, dirtyPolicyTrusted = true,
        policyRule = SelinuxPolicyRule(SelinuxPolicyRuleSet.DIRTY_SEPOLICY, "system_server execmem", SelinuxRuleVerdict.ALLOWED),
    )

    private fun carrier(state: AppZygoteCarrierSupportState) = SelinuxCheckResult(
        method = SelinuxOracle.CONTEXT_VALIDITY.label, status = SelinuxContextValidityVerdict.UNSUPPORTED.label,
        isSecure = null, permissionDenied = false, oracle = SelinuxOracle.CONTEXT_VALIDITY,
        contextValidity = SelinuxContextValidityReading(SelinuxContextValidityVerdict.UNSUPPORTED, state),
    )

    private fun reading(split: Boolean) = SelinuxSidtabReading(
        collection = SelinuxSidtabCollection.COMPLETE, attempted = true, completedRounds = 2,
        carrierVerified = true, canonicalMismatch = false, identityChanged = false, capturedUptimeMs = 1000,
        collectionDetails = SelinuxSidtabCollectionDetails("FINISHED", 0, "EXITED", 0, "u:r:app_zygote:s0", 10000, 123, "6.6", null),
        rounds = (0 until 2).map { index ->
            val before = 100L + index * 4
            SelinuxSidtabRound(before, before, before + if (split) 0 else 4, before + 4, before + 4, before + 4,
                true, (0 until 4).map { "u:r:app_zygote:s0:c${index * 4 + it}" }, true, true, true,
                positiveErrno = 0, negativeErrno = 22, stockContextsVerified = true, attrNegativeErrno = 22)
        },
    )
}
