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

package com.eltavine.duckdetector.features.tee.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceItem
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceSection
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkMode
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkState
import com.eltavine.duckdetector.features.tee.domain.TeeReport
import com.eltavine.duckdetector.features.tee.domain.TeeRkpState
import com.eltavine.duckdetector.features.tee.domain.TeeScanStage
import com.eltavine.duckdetector.features.tee.domain.TeeSignal
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import com.eltavine.duckdetector.features.tee.domain.TeeTrustRoot
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import com.eltavine.duckdetector.features.tee.ui.model.TeeFooterActionId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TeeCardModelMapperTest {

    private val mapper = TeeCardModelMapper()

    @Test
    fun `header facts prefer tamper score when present`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.TAMPERED,
                tier = TeeTier.TEE,
                headline = "Local anomaly indicators were detected",
                summary = "summary",
                collapsedSummary = "2 hard anomaly",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 72,
                evidenceCount = 8,
                signals = listOf(
                    TeeSignal("Local chain", "Failed", TeeSignalLevel.FAIL),
                    TeeSignal("CRL", "Active", TeeSignalLevel.PASS),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        title = "Checks",
                        items = listOf(
                            TeeEvidenceItem("Keystore2", "Java-style reply", TeeSignalLevel.FAIL),
                        ),
                    ),
                ),
                certificates = emptyList(),
                rkpState = TeeRkpState(provisioned = false),
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.ACTIVE,
                    summary = "clean",
                ),
                exportText = "export",
            ),
            isExpanded = true,
        )

        assertEquals(
            listOf("Verdict", "Tier", "Trust", "Score"),
            model.headerFacts.map { it.label })
        assertEquals("72", model.headerFacts.last().value)
        assertTrue(model.factGroups.single().rows.single().value.contains("Java-style"))
        assertTrue(model.actions.none { it.id == TeeFooterActionId.RESCAN })
        assertEquals("export", model.exportText)
    }

    @Test
    fun `skipped network state no longer exposes enable action`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Aligned",
                summary = "summary",
                collapsedSummary = "clean",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 0,
                evidenceCount = 0,
                signals = emptyList(),
                sections = emptyList(),
                certificates = emptyList(),
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.SKIPPED,
                    summary = "Online CRL disabled in Settings.",
                ),
            ),
            isExpanded = false,
        )

        assertTrue(model.actions.none { it.label.contains("CRL", ignoreCase = true) })
        assertEquals("Online CRL disabled in Settings.", model.networkState.summary)
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), model.networkState.status)
    }

    @Test
    fun `google rkp trust root exposes compact rkp badge`() {
        val rkpModel = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Aligned",
                summary = "summary",
                collapsedSummary = "clean",
                trustRoot = TeeTrustRoot.GOOGLE,
                localTrustChainLevel = TeeSignalLevel.PASS,
                trustSummary = "Google root with remote key provisioning",
                tamperScore = 0,
                evidenceCount = 0,
                signals = emptyList(),
                sections = emptyList(),
                certificates = emptyList(),
                rkpState = TeeRkpState(
                    provisioned = true,
                    serverSigned = true,
                ),
            ),
            isExpanded = false,
        )
        val regularModel = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Aligned",
                summary = "summary",
                collapsedSummary = "clean",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Google root",
                tamperScore = 0,
                evidenceCount = 0,
                signals = emptyList(),
                sections = emptyList(),
                certificates = emptyList(),
            ),
            isExpanded = false,
        )

        assertEquals("RKP", rkpModel.rkpBadgeLabel)
        assertNull(regularModel.rkpBadgeLabel)
    }

    @Test
    fun `supplementary local review keeps aligned verdict text but warns card status`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "Binder reply fingerprint matched a Java-hook style path. Attestation and trust-path checks still aligned.",
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.WARN,
                signals = listOf(
                    TeeSignal(
                        "Signals",
                        "0 policy hard • 0 policy review • 1 local",
                        TeeSignalLevel.WARN
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        title = "Checks",
                        items = listOf(
                            TeeEvidenceItem(
                                "Keystore2",
                                "Binder reply fingerprint matched a Java-hook style path.",
                                TeeSignalLevel.FAIL,
                                hiddenCopyText = "copy-me",
                            ),
                        ),
                    ),
                ),
                certificates = emptyList(),
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.INACTIVE,
                    summary = "Offline-only verification",
                ),
            ),
            isExpanded = false,
        )

        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals("Aligned + review", model.headerFacts.first { it.label == "Verdict" }.value)
        assertEquals("copy-me", model.factGroups.single().rows.single().hiddenCopyText)
    }

    @Test
    fun `tricky store timing skip signature escalates aligned tee card to danger`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "Detected malicious-module fingerprint during timing skip. Attestation and trust-path checks still aligned.",
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.WARN,
                signals = listOf(
                    TeeSignal(
                        "Signals",
                        "0 policy hard • 0 policy review • 1 local",
                        TeeSignalLevel.WARN,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        title = "Checks",
                        items = listOf(
                            TeeEvidenceItem(
                                "Timing side-channel",
                                "Detected malicious-module fingerprint • Register timer • bound_cpu0",
                                TeeSignalLevel.FAIL,
                            ),
                        ),
                    ),
                ),
                certificates = emptyList(),
            ),
            isExpanded = false,
        )

        assertEquals(DetectorStatus.danger(), model.status)
    }

    @Test
    fun `tee simulator timing skip signature escalates aligned tee card to danger`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "Detected malicious-module fingerprint during timing skip. Attestation and trust-path checks still aligned.",
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.WARN,
                signals = listOf(
                    TeeSignal(
                        "Signals",
                        "0 policy hard • 0 policy review • 1 local",
                        TeeSignalLevel.WARN,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        title = "Checks",
                        items = listOf(
                            TeeEvidenceItem(
                                "Timing side-channel",
                                "Detected malicious-module fingerprint • Fallback timer • not_requested",
                                TeeSignalLevel.FAIL,
                            ),
                        ),
                    ),
                ),
                certificates = emptyList(),
            ),
            isExpanded = false,
        )

        assertEquals(DetectorStatus.danger(), model.status)
    }

    @Test
    fun `matched tee simulator generate mode fingerprint escalates aligned tee card to danger`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "Matched TEE Simulator generate-mode fingerprint. Attestation and trust-path checks still aligned.",
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.WARN,
                signals = listOf(
                    TeeSignal(
                        "TEE Simulator generate-mode fingerprint",
                        "Matched",
                        TeeSignalLevel.FAIL,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        title = "Checks",
                        items = listOf(
                            TeeEvidenceItem(
                                "TEE Simulator generate-mode fingerprint",
                                "Matched TEE Simulator generate-mode fingerprint.",
                                TeeSignalLevel.FAIL,
                            ),
                        ),
                    ),
                ),
                certificates = emptyList(),
            ),
            isExpanded = false,
        )

        assertEquals(DetectorStatus.danger(), model.status)
    }

    @Test
    fun `rkp badge is hidden when local trust chain needs review`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.SUSPICIOUS,
                tier = TeeTier.TEE,
                headline = "Review",
                summary = "summary",
                collapsedSummary = "review",
                trustRoot = TeeTrustRoot.GOOGLE,
                localTrustChainLevel = TeeSignalLevel.WARN,
                trustSummary = "Google root, chain needs review",
                tamperScore = 16,
                evidenceCount = 1,
                signals = emptyList(),
                sections = emptyList(),
                certificates = emptyList(),
                rkpState = TeeRkpState(
                    provisioned = true,
                    serverSigned = true,
                ),
            ),
            isExpanded = false,
        )

        assertNull(model.rkpBadgeLabel)
        assertEquals(
            DetectorStatus.warning(),
            model.headerFacts.single { it.label == "Trust" }.status
        )
    }

    @Test
    fun `header tier shows strongbox when report tier is strongbox`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.STRONGBOX,
                headline = "Aligned",
                summary = "summary",
                collapsedSummary = "clean",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Google root",
                tamperScore = 0,
                evidenceCount = 0,
                signals = emptyList(),
                sections = emptyList(),
                certificates = emptyList(),
            ),
            isExpanded = false,
        )

        assertEquals("StrongBox", model.headerFacts.single { it.label == "Tier" }.value)
    }
}
