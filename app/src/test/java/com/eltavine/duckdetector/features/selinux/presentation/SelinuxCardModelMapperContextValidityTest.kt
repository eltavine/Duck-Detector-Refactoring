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

package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxContextValidityProbe
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxProcAttrCurrentProbe
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
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
                    method = SelinuxContextValidityProbe.METHOD_LABEL,
                    status = "",
                    isSecure = true,
                    permissionDenied = false,
                    details = "Root contexts were not found by live policy.",
                ),
            ),
        )

        assertEquals(DetectorStatus.allClear(), model.status)
        assertEquals("Enforcing", model.verdict)
        assertTrue(
            model.methodRows.any {
                it.label == SelinuxContextValidityProbe.METHOD_LABEL && it.value.isBlank()
            },
        )
    }

    @Test
    fun `root context validity maps to danger copy`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxContextValidityProbe.METHOD_LABEL,
                    status = SelinuxContextValidityProbe.BITPAIR_KSU_PRESENT,
                    isSecure = false,
                    permissionDenied = false,
                    details = "Both KSU-specific contexts were found by live policy.",
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
    fun `self test failure is warning not clean or root`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxContextValidityProbe.METHOD_LABEL,
                    status = SelinuxContextValidityProbe.BITPAIR_SELF_TEST_FAILED,
                    isSecure = null,
                    permissionDenied = false,
                    details = "Context validity oracle failed its self-test.",
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
                    method = SelinuxContextValidityProbe.METHOD_LABEL,
                    status = SelinuxContextValidityProbe.BITPAIR_UNSUPPORTED,
                    isSecure = null,
                    permissionDenied = false,
                    details = "Unavailable: u:r:app_zygote:s0 errno=Permission denied",
                ),
            ),
        )

        assertEquals(DetectorStatus.allClear(), model.status)
        assertEquals("Enforcing", model.verdict)
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
                    method = SelinuxContextValidityProbe.METHOD_LABEL,
                    status = SelinuxContextValidityProbe.BITPAIR_UNSUPPORTED,
                    isSecure = null,
                    permissionDenied = false,
                    details = "Evidence source=local native fallback | No preloaded data available. Check AppZygotePreload status.",
                ),
            ),
        )

        assertEquals(DetectorStatus.allClear(), model.status)
        assertEquals("Enforcing", model.verdict)
        assertTrue(model.summary.contains("No preloaded data available"))
        assertTrue(
            model.impactItems.any {
                it.text.contains("No preloaded data available")
            },
        )
        assertTrue(
            model.methodRows.any {
                it.label == SelinuxContextValidityProbe.METHOD_LABEL &&
                    it.detail?.contains("Evidence source=local native fallback") == true
            },
        )
    }

    @Test
    fun `repeatability failure is warning not clean or root`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxContextValidityProbe.METHOD_LABEL,
                    status = SelinuxContextValidityProbe.BITPAIR_SELF_TEST_FAILED,
                    isSecure = null,
                    permissionDenied = false,
                    details = "Context validity oracle repeatability failed.",
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
    fun `app zygote attr write anomaly maps to danger copy`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxContextValidityProbe.METHOD_LABEL,
                    status = SelinuxContextValidityProbe.BITPAIR_CLEAN,
                    isSecure = true,
                    permissionDenied = false,
                    details = "Pair 00",
                ),
                SelinuxCheckResult(
                    method = SelinuxProcAttrCurrentProbe.METHOD_LABEL,
                    status = "Detected: Magisk, LSPosed file",
                    isSecure = false,
                    permissionDenied = false,
                    details = "Magisk=DETECTED_NON_EINVAL | LSPosed file=SUCCESS",
                ),
            ),
        )

        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals("Enforcing with app_zygote attr-write anomaly", model.verdict)
        assertTrue(model.summary.contains("Magisk, LSPosed file"))
        assertTrue(
            model.impactItems.any {
                it.text.contains("anomalous /proc/self/attr/current writes")
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
