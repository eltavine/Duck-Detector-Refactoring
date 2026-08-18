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

package com.eltavine.duckdetector.features.bootloader.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderEvidenceMode
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFinding
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingGroup
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingSeverity
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodOutcome
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodResult
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderReport
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderStage
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderState
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import com.eltavine.duckdetector.features.tee.domain.TeeTrustRoot
import org.junit.Assert.assertEquals
import org.junit.Test

class BootloaderCardModelMapperTest {

    private val mapper = BootloaderCardModelMapper()

    @Test
    fun `unknown trust root with zero chain turns trust header and chain summary red`() {
        val model = mapper.map(
            report = report(
                trustRoot = TeeTrustRoot.UNKNOWN,
                attestationChainLength = 0,
                findings = listOf(
                    BootloaderFinding(
                        id = "trust_root",
                        label = "Trust root",
                        value = "Unknown",
                        group = BootloaderFindingGroup.STATE,
                        severity = BootloaderFindingSeverity.DANGER,
                    ),
                ),
            ),
        )

        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals(
            DetectorStatus.danger(),
            model.headerFacts.single { it.label == "Trust" }.status,
        )
        assertEquals(
            DetectorStatus.danger(),
            model.scanRows.single { it.label == "Attestation chain" }.status,
        )
    }

    @Test
    fun `key attestation key pair failure maps to danger rows`() {
        val model = mapper.map(
            report = report(
                findings = listOf(
                    BootloaderFinding(
                        id = "attestation_unavailable",
                        label = "Key attestation",
                        value = "Failed",
                        group = BootloaderFindingGroup.ATTESTATION,
                        severity = BootloaderFindingSeverity.DANGER,
                        detail = "failed to generate a key pair",
                    ),
                ),
                methods = listOf(
                    BootloaderMethodResult(
                        label = "Key attestation",
                        summary = "Failed",
                        outcome = BootloaderMethodOutcome.DANGER,
                        detail = "failed to generate a key pair",
                    ),
                ),
            ),
        )

        assertEquals(
            DetectorStatus.danger(),
            model.attestationRows.single { it.label == "Key attestation" }.status,
        )
        assertEquals(
            DetectorStatus.danger(),
            model.methodRows.single { it.label == "Key attestation" }.status,
        )
    }

    @Test
    fun `Widevine warning colors the card and renders unknown state`() {
        val model = mapper.map(
            report = report(
                state = BootloaderState.UNKNOWN,
                findings = listOf(
                    BootloaderFinding(
                        id = "widevine_credential",
                        label = "Widevine credential",
                        value = "Sentinel system ID",
                        group = BootloaderFindingGroup.CONSISTENCY,
                        severity = BootloaderFindingSeverity.WARNING,
                        detail = "DRM credential anomaly made the state inconclusive.",
                    ),
                ),
                methods = listOf(
                    BootloaderMethodResult(
                        label = "Widevine credential",
                        summary = "Needs review",
                        outcome = BootloaderMethodOutcome.WARNING,
                    ),
                ),
                consistencyFindingCount = 1,
            ),
        )

        assertEquals("Unknown", model.headerFacts.single { it.label == "State" }.value)
        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals("1 DRM consistency signal(s) need review", model.verdict)
        assertEquals(
            DetectorStatus.warning(),
            model.consistencyRows.single { it.label == "Widevine credential" }.status,
        )
        assertEquals(
            DetectorStatus.warning(),
            model.methodRows.single { it.label == "Widevine credential" }.status,
        )
        assertEquals(
            DetectorStatus.warning(),
            model.scanRows.single { it.label == "Cross-checks" }.status,
        )
    }

    @Test
    fun `Widevine danger colors the card and renders unlocked state`() {
        val model = mapper.map(
            report = report(
                state = BootloaderState.UNLOCKED,
                findings = listOf(
                    BootloaderFinding(
                        id = "widevine_credential",
                        label = "Widevine credential",
                        value = "Corroborated anomaly",
                        group = BootloaderFindingGroup.CONSISTENCY,
                        severity = BootloaderFindingSeverity.DANGER,
                    ),
                ),
                methods = listOf(
                    BootloaderMethodResult(
                        label = "Widevine credential",
                        summary = "DRM inconsistency",
                        outcome = BootloaderMethodOutcome.DANGER,
                    ),
                ),
                consistencyFindingCount = 1,
            ),
        )

        assertEquals("Unlocked", model.headerFacts.single { it.label == "State" }.value)
        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals("1 critical DRM consistency signal(s)", model.verdict)
        assertEquals(
            DetectorStatus.danger(),
            model.consistencyRows.single { it.label == "Widevine credential" }.status,
        )
        assertEquals(
            DetectorStatus.danger(),
            model.scanRows.single { it.label == "Cross-checks" }.status,
        )
    }

    private fun report(
        state: BootloaderState = BootloaderState.VERIFIED,
        trustRoot: TeeTrustRoot = TeeTrustRoot.GOOGLE,
        attestationChainLength: Int = 2,
        findings: List<BootloaderFinding> = emptyList(),
        methods: List<BootloaderMethodResult> = emptyList(),
        consistencyFindingCount: Int = 0,
    ): BootloaderReport {
        return BootloaderReport(
            stage = BootloaderStage.READY,
            state = state,
            evidenceMode = BootloaderEvidenceMode.ATTESTATION,
            trustRoot = trustRoot,
            tier = TeeTier.TEE,
            attestationAvailable = attestationChainLength > 0,
            hardwareBacked = true,
            attestationChainLength = attestationChainLength,
            checkedPropertyCount = 8,
            observedPropertyCount = 8,
            nativePropertyHitCount = 4,
            rawBootParamHitCount = 2,
            sourceMismatchCount = 0,
            consistencyFindingCount = consistencyFindingCount,
            findings = findings,
            impacts = emptyList(),
            methods = methods,
        )
    }
}
