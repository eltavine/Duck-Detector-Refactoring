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
    fun `clean context validity maps to all clear copy`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxContextValidityProbe.METHOD_LABEL,
                    status = SelinuxContextValidityProbe.BITPAIR_CLEAN,
                    isSecure = true,
                    permissionDenied = false,
                    details = "Pair 00",
                ),
            ),
        )

        assertEquals(DetectorStatus.allClear(), model.status)
        assertEquals("Enforcing", model.verdict)
        assertTrue(model.summary.contains("rejected both KSU-specific contexts"))
        assertTrue(
            model.impactItems.any {
                it.text.contains("rejected both KSU-specific contexts")
            },
        )
    }

    @Test
    fun `ksu context validity maps to danger copy`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxContextValidityProbe.METHOD_LABEL,
                    status = SelinuxContextValidityProbe.BITPAIR_KSU_PRESENT,
                    isSecure = false,
                    permissionDenied = false,
                    details = "Pair 11",
                ),
            ),
        )

        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals("Enforcing with KSU context materialized", model.verdict)
        assertTrue(model.summary.contains("accepted both KSU-specific contexts"))
        assertTrue(
            model.methodRows.any {
                it.label == SelinuxContextValidityProbe.METHOD_LABEL &&
                    it.value == SelinuxContextValidityProbe.BITPAIR_KSU_PRESENT
            },
        )
    }

    @Test
    fun `self test failure is not treated as ksu or clean`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = SelinuxContextValidityProbe.METHOD_LABEL,
                    status = SelinuxContextValidityProbe.BITPAIR_SELF_TEST_FAILED,
                    isSecure = null,
                    permissionDenied = false,
                    details = "Oracle self-test failed.",
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
        assertTrue(
            model.methodRows.any {
                it.label == SelinuxContextValidityProbe.METHOD_LABEL &&
                    it.value == SelinuxContextValidityProbe.BITPAIR_SELF_TEST_FAILED
            },
        )
    }

    @Test
    fun `repeatability failure maps to unstable oracle copy`() {
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

    private fun baseReport(contextResult: SelinuxCheckResult): SelinuxReport {
        return SelinuxReport(
            stage = SelinuxStage.READY,
            mode = SelinuxMode.ENFORCING,
            resolvedStatusLabel = "Enforcing",
            filesystemMounted = true,
            paradoxDetected = false,
            methods = listOf(contextResult),
            processContext = "u:r:untrusted_app:s0:c1,c2",
            contextType = "untrusted_app",
            policyAnalysis = null,
            auditIntegrity = null,
            androidVersion = "16",
            apiLevel = 36,
        )
    }
}
