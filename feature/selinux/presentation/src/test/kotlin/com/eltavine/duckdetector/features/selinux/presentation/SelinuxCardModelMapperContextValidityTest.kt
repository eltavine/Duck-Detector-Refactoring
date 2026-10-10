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
import com.eltavine.duckdetector.features.selinux.domain.AppZygoteCarrierSupportState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxContextValidityReading
import com.eltavine.duckdetector.features.selinux.domain.SelinuxContextValidityVerdict
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyloadSeqnoLabels
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxCardModelMapperContextValidityTest {

    private val mapper = SelinuxCardModelMapper()

    @Test
    fun `clean context validity keeps enforcing copy all clear`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxOracle.CONTEXT_VALIDITY.label,
                    status = "",
                    isSecure = true,
                    permissionDenied = false,
                    details = "Root contexts were not found by live policy.",
                    oracle = SelinuxOracle.CONTEXT_VALIDITY,
                ),
            ),
        )

        assertEquals(DetectorStatus.allClear(), model.status)
        assertEquals("Enforcing", model.verdict)
        assertEquals("7 local checks", model.subtitle)
        assertTrue(
            model.methodRows.any {
                it.label == SelinuxOracle.CONTEXT_VALIDITY.label && it.value.isBlank()
            },
        )
    }

    @Test
    fun `root context validity maps to danger copy`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxOracle.CONTEXT_VALIDITY.label,
                    status = SelinuxContextValidityVerdict.KSU_PRESENT.label,
                    isSecure = false,
                    permissionDenied = false,
                    details = "Both KSU-specific contexts were found by live policy.",
                    oracle = SelinuxOracle.CONTEXT_VALIDITY,
                    contextValidity = SelinuxContextValidityReading(SelinuxContextValidityVerdict.KSU_PRESENT, AppZygoteCarrierSupportState.AVAILABLE),
                ),
            ),
        )

        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals("Enforcing with KSU context materialized", model.verdict)
        assertTrue(model.summary.contains("accepted both KSU-specific contexts"))
        assertTrue(
            model.impactItems.any {
                it.text.contains("validated both KSU-specific contexts") ||
                    it.text.contains("accepted both KSU-specific contexts")
            },
        )
    }

    @Test
    fun `context validity root verdict still wins over clean seqno`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxOracle.CONTEXT_VALIDITY.label,
                    status = SelinuxContextValidityVerdict.KSU_PRESENT.label,
                    isSecure = false,
                    permissionDenied = false,
                    details = "Both KSU-specific contexts were found by live policy.",
                    oracle = SelinuxOracle.CONTEXT_VALIDITY,
                    contextValidity = SelinuxContextValidityReading(SelinuxContextValidityVerdict.KSU_PRESENT, AppZygoteCarrierSupportState.AVAILABLE),
                ),
                SelinuxCheckResult(
                    method = SelinuxOracle.POLICYLOAD_SEQNO.label,
                    status = SelinuxPolicyloadSeqnoLabels.STATUS_CLEAN,
                    isSecure = true,
                    permissionDenied = false,
                    details = "status.policyload=9 | access.avd.seqno=9",
                    oracle = SelinuxOracle.POLICYLOAD_SEQNO,
                ),
            ),
        )

        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals("Enforcing with KSU context materialized", model.verdict)
        assertTrue(model.summary.contains("accepted both KSU-specific contexts"))
        assertTrue(
            model.methodRows.any {
                it.label == SelinuxOracle.POLICYLOAD_SEQNO.label &&
                    it.status == DetectorStatus.allClear()
            },
        )
    }

    @Test
    fun `self test failure is warning not clean or root`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxOracle.CONTEXT_VALIDITY.label,
                    status = SelinuxContextValidityVerdict.SELF_TEST_FAILED.label,
                    isSecure = null,
                    permissionDenied = false,
                    details = "Context validity oracle failed its self-test.",
                    oracle = SelinuxOracle.CONTEXT_VALIDITY,
                    contextValidity = SelinuxContextValidityReading(SelinuxContextValidityVerdict.SELF_TEST_FAILED, AppZygoteCarrierSupportState.AVAILABLE),
                ),
            ),
        )

        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals("Enforcing with untrusted context oracle", model.verdict)
        assertTrue(model.summary.contains("failed its self-test"))
        assertTrue(
            model.impactItems.any {
                it.text.contains("failed its self-test")
            },
        )
    }

    @Test
    fun `blocked app zygote selinux query is warning not clean or root`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxOracle.CONTEXT_VALIDITY.label,
                    status = SelinuxContextValidityVerdict.UNSUPPORTED.label,
                    isSecure = null,
                    permissionDenied = false,
                    details = "Carrier=<unreadable> | Carrier state=failed | Evidence source=dedicated app_zygote carrier | Unavailable: u:r:app_zygote:s0 errno=Permission denied",
                    oracle = SelinuxOracle.CONTEXT_VALIDITY,
                    contextValidity = SelinuxContextValidityReading(SelinuxContextValidityVerdict.UNSUPPORTED, AppZygoteCarrierSupportState.FAILED),
                ),
            ),
        )

        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), model.status)
        assertEquals("Enforcing with reduced app_zygote coverage", model.verdict)
        assertTrue(model.summary.contains("Unavailable: u:r:app_zygote:s0 errno=Permission denied"))
        assertTrue(
            model.impactItems.any {
                it.text.contains("Unavailable: u:r:app_zygote:s0 errno=Permission denied")
            },
        )
    }

    @Test
    fun `unavailable oracle is surfaced as support rather than clean`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxOracle.CONTEXT_VALIDITY.label,
                    status = SelinuxContextValidityVerdict.UNSUPPORTED.label,
                    isSecure = null,
                    permissionDenied = false,
                    details = "Carrier=<unreadable> | Carrier state=failed | Evidence source=dedicated app_zygote carrier | No preloaded data available. Check AppZygotePreload status.",
                    oracle = SelinuxOracle.CONTEXT_VALIDITY,
                    contextValidity = SelinuxContextValidityReading(SelinuxContextValidityVerdict.UNSUPPORTED, AppZygoteCarrierSupportState.FAILED),
                ),
            ),
        )

        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), model.status)
        assertEquals("Enforcing with reduced app_zygote coverage", model.verdict)
        assertTrue(model.summary.contains("No preloaded data available"))
        assertTrue(
            model.impactItems.any {
                it.text.contains("No preloaded data available")
            },
        )
        assertTrue(
            model.methodRows.any {
                it.label == SelinuxOracle.CONTEXT_VALIDITY.label &&
                    it.detail?.contains("Evidence source=dedicated app_zygote carrier") == true
            },
        )
    }

    @Test
    fun `untrusted app zygote carrier is warning not clean`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxOracle.CONTEXT_VALIDITY.label,
                    status = SelinuxContextValidityVerdict.UNSUPPORTED.label,
                    isSecure = null,
                    permissionDenied = false,
                    details = "Carrier=u:r:untrusted_app:s0:c1,c2 | Carrier state=untrusted | Evidence source=dedicated app_zygote carrier | The dedicated app_zygote carrier was reachable but did not land in the expected app_zygote context.",
                    oracle = SelinuxOracle.CONTEXT_VALIDITY,
                    contextValidity = SelinuxContextValidityReading(SelinuxContextValidityVerdict.UNSUPPORTED, AppZygoteCarrierSupportState.UNTRUSTED),
                ),
            ),
        )

        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals("Enforcing with untrusted app_zygote carrier", model.verdict)
        assertTrue(model.summary.contains("did not land in the expected app_zygote context"))
    }

    @Test
    fun `repeatability failure is warning not clean or root`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxOracle.CONTEXT_VALIDITY.label,
                    status = SelinuxContextValidityVerdict.SELF_TEST_FAILED.label,
                    isSecure = null,
                    permissionDenied = false,
                    details = "Context validity oracle repeatability failed.",
                    oracle = SelinuxOracle.CONTEXT_VALIDITY,
                    contextValidity = SelinuxContextValidityReading(SelinuxContextValidityVerdict.SELF_TEST_FAILED, AppZygoteCarrierSupportState.AVAILABLE, repeatabilityFailed = true),
                ),
            ),
        )

        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals("Enforcing with unstable context oracle", model.verdict)
        assertTrue(model.summary.contains("repeated inconsistently"))
        assertTrue(
            model.impactItems.any {
                it.text.contains("repeated inconsistently")
            },
        )
    }

    @Test
    fun `unavailable app zygote seqno stays info not warning`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxOracle.POLICYLOAD_SEQNO.label,
                    status = SelinuxPolicyloadSeqnoLabels.STATUS_UNAVAILABLE,
                    isSecure = null,
                    permissionDenied = false,
                    details = "zygotePreloadName required=yes | Probe attempted=no",
                    oracle = SelinuxOracle.POLICYLOAD_SEQNO,
                ),
            ),
        )

        assertEquals(DetectorStatus.allClear(), model.status)
        assertEquals("Enforcing", model.verdict)
        assertTrue(
            model.methodRows.any {
                it.label == SelinuxOracle.POLICYLOAD_SEQNO.label &&
                    it.status == DetectorStatus.info(InfoKind.SUPPORT)
            },
        )
        assertTrue(
            model.impactItems.any {
                it.text.contains("zygotePreloadName required=yes") &&
                    it.status == DetectorStatus.info(InfoKind.SUPPORT)
            },
        )
    }

    @Test
    fun `app zygote seqno split maps to danger`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxOracle.POLICYLOAD_SEQNO.label,
                    status = SelinuxPolicyloadSeqnoLabels.STATUS_SUSPICIOUS,
                    isSecure = false,
                    permissionDenied = false,
                    details = "status.policyload=0 | access.avd.seqno=9",
                    oracle = SelinuxOracle.POLICYLOAD_SEQNO,
                ),
            ),
        )

        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals("Enforcing with app_zygote seqno split", model.verdict)
        assertTrue(model.summary.contains("policyload/access seqno split"))
        assertTrue(
            model.methodRows.any {
                it.label == SelinuxOracle.POLICYLOAD_SEQNO.label &&
                    it.status == DetectorStatus.danger()
            },
        )
    }

    @Test
    fun `controlled context recognition maps to supporting warning copy`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxOracle.CONTEXT_VALIDITY.label,
                    status = SelinuxContextValidityVerdict.CLEAN.label,
                    isSecure = true,
                    permissionDenied = false,
                    details = "Pair 00",
                    oracle = SelinuxOracle.CONTEXT_VALIDITY,
                    contextValidity = SelinuxContextValidityReading(SelinuxContextValidityVerdict.CLEAN, AppZygoteCarrierSupportState.AVAILABLE),
                ),
                SelinuxCheckResult(
                    method = SelinuxOracle.PROC_ATTR_CURRENT_WRITE.label,
                    status = "Context recognized: Magisk, LSPosed file",
                    isSecure = false,
                    permissionDenied = false,
                    details = "Controls=CONTROLS_PASSED | Magisk=CONTEXT_RECOGNIZED | LSPosed file=CONTEXT_RECOGNIZED",
                    oracle = SelinuxOracle.PROC_ATTR_CURRENT_WRITE,
                    attrCurrentDetections = listOf("Magisk", "LSPosed file"),
                ),
            ),
        )

        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals("Enforcing with recognized privileged contexts", model.verdict)
        assertTrue(model.summary.contains("Magisk, LSPosed file"))
        assertTrue(
            model.impactItems.any {
                it.status == DetectorStatus.warning() && it.text.contains("Controlled attr/current writes")
            },
        )
    }

    private fun baseReport(vararg methods: SelinuxCheckResult): SelinuxReport {
        return SelinuxReport(
            stage = SelinuxStage.READY,
            mode = SelinuxMode.ENFORCING,
            resolvedStatusLabel = "Enforcing",
            filesystemMounted = true,
            paradoxDetected = false,
            methods = methods.toList(),
            processContext = "u:r:untrusted_app:s0:c1,c2",
            contextType = "untrusted_app",
            policyAnalysis = null,
            auditIntegrity = null,
            androidVersion = "16",
            apiLevel = 36,
        )
    }
}
