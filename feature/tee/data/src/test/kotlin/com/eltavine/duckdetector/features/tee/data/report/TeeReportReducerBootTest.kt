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

package com.eltavine.duckdetector.features.tee.data.report

import com.eltavine.duckdetector.capability.attestation.data.BootConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.certificate.ChainStructureResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateSecurityLevelResult
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TeeReportReducerBootTest {

    private val reducer = TeeReportReducer()

    @Test
    fun `readable runtime properties without comparison remain informational`() {
        val report = reducer.reduce(baseArtifacts(bootConsistency = BootConsistencyResult(
            runtimePropsAvailable = true,
            runtimeVbmetaDigest = "aabb",
            runtimeComparisonPerformed = false,
        )))

        assertEquals(TeeSignalLevel.INFO, report.signals.single { it.label == "Boot" }.level)
        val row = report.sections.single { it.title == "Attestation" }.items
            .single { it.title == "Boot consistency" }
        assertEquals(TeeSignalLevel.INFO, row.level)
        assertTrue(row.body.startsWith("State only"))
    }

    @Test
    fun `pure certificate top level and metadata security levels render as separate checks`() {
        val report = reducer.reduce(
            baseArtifacts(
                pureCertificateSecurityLevel = PureCertificateSecurityLevelResult(
                    executed = true,
                    securityLevelPresent = false,
                    metadataSecurityLevelPresent = true,
                    detail = "metadata keySecurityLevel present",
                ),
            ),
        )

        val checks = report.sections.single { it.title == "Checks" }.items
        assertTrue(checks.any {
            it.title == "Pure cert level" && it.body == "No security level exposed"
        })
        assertTrue(checks.any {
            it.title == "Pure cert metadata" && it.body == "Metadata security level exposed"
        })
    }

    @Test
    fun `provisioning layout anomaly becomes suspicious verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                chainStructure = ChainStructureResult(
                    chainLength = 4,
                    attestationExtensionCount = 1,
                    trustedAttestationIndex = 2,
                    provisioningIndex = 0,
                    provisioningConsistencyIssue = true,
                    detail = "provisioning",
                ),
            ),
        )

        assertEquals(TeeVerdict.SUSPICIOUS, report.verdict)
        assertTrue(report.sections.single { it.title == "Trust" }.items.any { it.title == "Chain layout" })
        assertTrue(report.summary.contains("adjacent", ignoreCase = true))
    }

    @Test
    fun `vbmeta digest mismatch becomes tampered verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                bootConsistency = BootConsistencyResult(
                    vbmetaDigestMismatch = true,
                    runtimePropsAvailable = true,
                    runtimeVbmetaDigest = "ffee",
                    detail = "Attested verifiedBootHash did not match ro.boot.vbmeta.digest.",
                ),
            ),
        )

        assertEquals(TeeVerdict.TAMPERED, report.verdict)
        assertTrue(report.signals.any { it.label == "Boot" && it.value == "Mismatch" })
        assertTrue(report.sections.single { it.title == "Attestation" }.items.any {
            it.title == "Boot consistency" && it.body.contains("Mismatch")
        })
    }

    @Test
    fun `verified state unlocked mismatch no longer creates a hard anomaly`() {
        val report = reducer.reduce(
            baseArtifacts(
                bootConsistency = BootConsistencyResult(
                    runtimePropsAvailable = true,
                    detail = "Attestation reported Verified while deviceLocked=false; AOSP allows this on approved test devices, so no anomaly was raised.",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.single { it.title == "Attestation" }.items.any {
            it.title == "Boot consistency" && it.body.contains("State only")
        })
    }

    @Test
    fun `zeroed verified boot hash becomes tampered verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                bootConsistency = BootConsistencyResult(
                    verifiedBootHashAllZeros = true,
                    runtimePropsAvailable = true,
                    detail = "Attested verifiedBootHash was all zeros.",
                ),
            ),
        )

        assertEquals(TeeVerdict.TAMPERED, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any { it.title == "Indicators" })
    }
}
