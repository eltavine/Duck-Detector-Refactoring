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
    fun `skipped online refresh state no longer exposes enable action`() {
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
                    summary = "Built-in revocation snapshot is active; online refresh is disabled in Settings.",
                    usedCache = true,
                ),
            ),
            isExpanded = false,
        )

        assertTrue(model.actions.none { it.label.contains("CRL", ignoreCase = true) })
        assertEquals(
            "Built-in revocation snapshot is active; online refresh is disabled in Settings.",
            model.networkState.summary,
        )
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
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
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
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
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
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
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
                                hiddenCopyText = "reply raw hex dump",
                            ),
                        ),
                    ),
                ),
                certificates = emptyList(),
            ),
            isExpanded = false,
        )

        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals(
            "reply raw hex dump",
            model.factGroups.single().rows.single().hiddenCopyText,
        )
    }

    @Test
    fun `matched importKey retained narrative escalates aligned tee card to danger`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "ImportKey retained attestation narrative detected. Attestation and trust-path checks still aligned.",
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal(
                        "ImportKey narrative",
                        "Matched",
                        TeeSignalLevel.FAIL,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        title = "Checks",
                        items = listOf(
                            TeeEvidenceItem(
                                "ImportKey narrative",
                                "Matched • kind=STALE_GENERATED_AFTER_IMPORT, origin=GENERATED, retained=3",
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
    fun `matched grant isolated-domain split escalates aligned tee card to danger`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "Grant isolated-domain certificate-chain narrative split detected. Attestation and trust-path checks still aligned.",
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal(
                        "Grant isolated-domain",
                        "Matched",
                        TeeSignalLevel.FAIL,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        title = "Checks",
                        items = listOf(
                            TeeEvidenceItem(
                                "Grant isolated-domain",
                                "Matched kind=ISOLATED_CHAIN_SPLIT • mismatchIndex=2 • owner=3 grantee=2",
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
    fun `grant isolated-domain key visibility divergence escalates aligned tee card to danger`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "Grant isolated-domain key visibility divergence detected. Attestation and trust-path checks still aligned.",
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal(
                        "Grant isolated-domain",
                        "Unavailable",
                        TeeSignalLevel.FAIL,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        title = "Checks",
                        items = listOf(
                            TeeEvidenceItem(
                                "Grant isolated-domain",
                                "Unavailable kind=ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN • private grant failed: ServiceSpecificException(code 7): No key found by the given alias",
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
    fun `grant caller binding failure escalates aligned tee card to danger`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "Grant handle remained readable by its non-grantee owner. Attestation and trust-path checks still aligned.",
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal("Grant caller binding", "Matched", TeeSignalLevel.FAIL),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        title = "Checks",
                        items = listOf(
                            TeeEvidenceItem(
                                "Grant caller binding",
                                "Matched kind=NON_GRANTEE_READBACK_ALLOWED uid=99001 ownerReplay=true",
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
        assertEquals(
            "Grant handle caller binding failed; open TEE details for stage diagnostics.",
            model.findingDetail,
        )
    }

    @Test
    fun `grant isolated-domain private readback crash shows warning card and compact finding detail`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "Grant isolated-domain isolated private readback crashed after grant succeeded. Attestation and trust-path checks still aligned.",
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.WARN,
                signals = listOf(
                    TeeSignal(
                        "Grant isolated-domain",
                        "Warn",
                        TeeSignalLevel.WARN,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        title = "Checks",
                        items = listOf(
                            TeeEvidenceItem(
                                "Grant isolated-domain",
                                "Grant isolated-domain isolated private readback crashed after grant succeeded. kind=ISOLATED_PRIVATE_READBACK_CRASH owner=3 uid=99001",
                                TeeSignalLevel.WARN,
                                hiddenCopyText = "java.lang.reflect.InvocationTargetException\nCaused by: android.os.ServiceSpecificException: system/security/keystore2/src/service.rs:157: while trying to load key info.\n\nCaused by:\n    0: No legacy keys for key descriptor.\n    1: Error::Rc(r#KEY_NOT_FOUND) (code 7)",
                            ),
                        ),
                    ),
                ),
                certificates = emptyList(),
            ),
            isExpanded = false,
        )

        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals(
            "Grant isolated-domain runtime crash; open TEE details for stage diagnostics.",
            model.findingDetail,
        )
        assertEquals(
            "java.lang.reflect.InvocationTargetException\nCaused by: android.os.ServiceSpecificException: system/security/keystore2/src/service.rs:157: while trying to load key info.\n\nCaused by:\n    0: No legacy keys for key descriptor.\n    1: Error::Rc(r#KEY_NOT_FOUND) (code 7)",
            model.factGroups.single().rows.single().hiddenCopyText,
        )
    }

    @Test
    fun `matched grant self-domain split escalates aligned tee card to danger`() {
        val longGrantSummary =
            "Grant self-domain certificate-chain split detected. " +
                "Public: clean | Hidden: clean | Private: owner=3 grant=2 mismatchIndex=2. " +
                "Attestation and trust-path checks still aligned."
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = longGrantSummary,
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal(
                        "Grant self-domain",
                        "Matched",
                        TeeSignalLevel.FAIL,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        title = "Checks",
                        items = listOf(
                            TeeEvidenceItem(
                                "Grant self-domain",
                                "Matched kind=SELF_CHAIN_SPLIT owner=3 grant=2 mismatchIndex=2",
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
        assertEquals(longGrantSummary, model.summary)
        assertEquals(
            "Grant self-domain certificate chain diverged; open TEE details for stage diagnostics.",
            model.findingDetail,
        )
    }

    @Test
    fun `matched grant self-domain key visibility divergence escalates aligned tee card to danger`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "Grant self-domain key visibility divergence detected. Attestation and trust-path checks still aligned.",
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal(
                        "Grant self-domain",
                        "Unavailable",
                        TeeSignalLevel.FAIL,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        title = "Checks",
                        items = listOf(
                            TeeEvidenceItem(
                                "Grant self-domain",
                                "Unavailable kind=SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN owner=4 • private grant failed: ServiceSpecificException(code 7): No key found by the given alias",
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
    fun `matched update persistence stale narrative escalates aligned tee card to danger`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "UpdateSubcomponent stale TEE response persistence detected. Attestation and trust-path checks still aligned.",
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal(
                        "Update persistence",
                        "Matched",
                        TeeSignalLevel.FAIL,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        title = "Checks",
                        items = listOf(
                            TeeEvidenceItem(
                                "Update persistence",
                                "Matched kind=STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE retained=1 prior=3 post=2",
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
    fun `structured supplementary failure drives danger even when warning row appears first`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "UpdateSubcomponent stale TEE response persistence detected. Attestation and trust-path checks still aligned.",
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 2,
                supplementaryIndicatorCount = 2,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal(
                        "Signals",
                        "0 policy hard • 0 policy review • 2 local",
                        TeeSignalLevel.FAIL,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        title = "Checks",
                        items = listOf(
                            TeeEvidenceItem(
                                "Soter",
                                "Review abnormal Soter environment.",
                                TeeSignalLevel.WARN,
                            ),
                            TeeEvidenceItem(
                                "Update persistence",
                                "Matched kind=STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE retained=1",
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
    fun `structured supplementary failure drives danger even under suspicious verdict`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.SUSPICIOUS,
                tier = TeeTier.TEE,
                headline = "Policy-backed attestation evidence needs review",
                summary = "Provisioning info was not adjacent to the trusted attestation certificate.",
                collapsedSummary = "1 policy review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Google root, chain needs review",
                tamperScore = 18,
                evidenceCount = 2,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal(
                        "Signals",
                        "0 policy hard • 1 policy review • 1 local",
                        TeeSignalLevel.FAIL,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        title = "Trust",
                        items = listOf(
                            TeeEvidenceItem(
                                "Chain layout",
                                "Provisioning info was not adjacent to the trusted attestation certificate.",
                                TeeSignalLevel.WARN,
                            ),
                        ),
                    ),
                    TeeEvidenceSection(
                        title = "Checks",
                        items = listOf(
                            TeeEvidenceItem(
                                "Update persistence",
                                "Matched kind=STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE retained=1",
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
