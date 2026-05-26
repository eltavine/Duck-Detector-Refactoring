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

package com.eltavine.duckdetector.features.tee.data.report

import com.eltavine.duckdetector.features.tee.data.attestation.AttestationSnapshot
import com.eltavine.duckdetector.features.tee.data.attestation.AttestedApplicationInfo
import com.eltavine.duckdetector.features.tee.data.attestation.AttestedAuthState
import com.eltavine.duckdetector.features.tee.data.attestation.AttestedDeviceInfo
import com.eltavine.duckdetector.features.tee.data.attestation.AttestedKeyProperties
import com.eltavine.duckdetector.features.tee.data.attestation.RootOfTrustSnapshot
import com.eltavine.duckdetector.features.tee.data.native.NativeTeeSnapshot
import com.eltavine.duckdetector.features.tee.data.verification.certificate.ChainStructureResult
import com.eltavine.duckdetector.features.tee.data.verification.certificate.CertificateTrustResult
import com.eltavine.duckdetector.features.tee.data.verification.certificate.DualAlgorithmChainResult
import com.eltavine.duckdetector.features.tee.data.verification.crl.CrlStatusResult
import com.eltavine.duckdetector.features.tee.data.verification.crl.RevokedCertificate
import com.eltavine.duckdetector.features.tee.data.verification.crl.RevokedCertificateEvidenceKind
import com.eltavine.duckdetector.features.tee.data.verification.boot.BootConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.IdAttestationResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderChainConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderHookBootstrapResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderPatchModeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BiometricTeeIntegrationResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainFullChainSplitResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainFullChainSplitResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGetKeyEntryAccessVectorBlindnessResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ImportKeyRetainedAttestationAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ImportKeyRetainedAttestationNarrativeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataSemanticsResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataShapeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GenerateModeParcelFingerprintResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.LegacyKeystorePathResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesBatchedResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationErrorPathResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationPruningResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateSecurityLevelResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingSideChannelResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentStaleResponseAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentStaleResponsePersistenceResult
import com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorResult
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkMode
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkState
import com.eltavine.duckdetector.features.tee.domain.TeeRkpState
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeSoterState
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import com.eltavine.duckdetector.features.tee.domain.TeeTrustRoot
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TeeReportReducerTest {

    private val reducer = TeeReportReducer()

    @Test
    fun `java hook becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                keystore2Hook = Keystore2HookResult(
                    available = true,
                    javaHookDetected = true,
                    detail = "hooked",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("Java-hook", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Keystore2" && it.body.contains(
                "Java-style"
            )
        })
    }

    @Test
    fun `metadata semantics anomaly becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                keyMetadataSemantics = KeyMetadataSemanticsResult(
                    executed = true,
                    usesKeyIdDomain = false,
                    aliasCleared = false,
                    detail = "domain=0 alias=test",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.summary.contains("KEY_ID", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Metadata key" && it.body.contains("Descriptor mismatch")
        })
    }

    @Test
    fun `generate mode parcel fingerprint anomaly becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                generateModeParcelFingerprint = Keystore2GenerateModeParcelFingerprintResult(
                    executed = true,
                    available = true,
                    matched = true,
                    diagnosticCopyText = "reply raw hex dump",
                    detail = "malicious-module generate-mode parcel fingerprint observed",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("TEE Simulator generate-mode fingerprint", ignoreCase = true))
        assertTrue(report.signals.take(4).any { it.label == "Signals" })
        assertTrue(report.signals.any {
            it.label == "TEE Simulator generate-mode fingerprint" && it.value == "Matched"
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "TEE Simulator generate-mode fingerprint" &&
                it.body.contains("TEE Simulator generate-mode fingerprint", ignoreCase = true) &&
                it.hiddenCopyText == "reply raw hex dump"
        })
        assertFalse(report.exportText.contains("reply raw hex dump"))
    }

    @Test
    fun `generate mode parcel fingerprint clean state stays out of supplementary review`() {
        val report = reducer.reduce(
            baseArtifacts(
                generateModeParcelFingerprint = Keystore2GenerateModeParcelFingerprintResult(
                    executed = true,
                    available = true,
                    matched = false,
                    diagnosticCopyText = "clean diagnostic",
                    detail = "clean",
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "TEE Simulator generate-mode fingerprint" &&
                it.body.contains("No TEE Simulator generate-mode fingerprint observed.", ignoreCase = true) &&
                it.hiddenCopyText == "clean diagnostic"
        })
    }

    @Test
    fun `generate mode parcel fingerprint unavailable state stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                generateModeParcelFingerprint = Keystore2GenerateModeParcelFingerprintResult(
                    executed = false,
                    available = false,
                    diagnosticCopyText = "unavailable diagnostic",
                    detail = "unavailable",
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "TEE Simulator generate-mode fingerprint" &&
                it.body.contains("probe unavailable", ignoreCase = true) &&
            it.hiddenCopyText == "unavailable diagnostic"
        })
    }

    @Test
    fun `importKey retained narrative becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                importKeyRetainedAttestationNarrative = ImportKeyRetainedAttestationNarrativeResult(
                    executed = true,
                    importSupported = true,
                    markerImportBaselineClean = true,
                    originImported = true,
                    retainedNarrativeDetected = true,
                    priorChainLength = 3,
                    postImportChainLength = 2,
                    retainedCertificateCount = 2,
                    originLabel = "IMPORTED",
                    anomalyKind = ImportKeyRetainedAttestationAnomalyKind.IMPORTED_RETAINED_PRIOR_CHAIN,
                    retainedFingerprint = "abc123def456",
                    detail = "kind=IMPORTED_RETAINED_PRIOR_CHAIN, origin=IMPORTED, retained=2",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("ImportKey retained attestation narrative", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "ImportKey narrative" &&
                it.body.contains("Matched", ignoreCase = true) &&
                it.level == TeeSignalLevel.FAIL
        })
    }

    @Test
    fun `stale generated importKey retained narrative becomes supplementary review`() {
        val report = reducer.reduce(
            baseArtifacts(
                importKeyRetainedAttestationNarrative = ImportKeyRetainedAttestationNarrativeResult(
                    executed = true,
                    importSupported = true,
                    markerImportBaselineClean = true,
                    originImported = false,
                    postImportLeafMatchesMarker = false,
                    retainedNarrativeDetected = true,
                    priorChainLength = 3,
                    postImportChainLength = 3,
                    retainedCertificateCount = 3,
                    originLabel = "GENERATED",
                    anomalyKind = ImportKeyRetainedAttestationAnomalyKind.STALE_GENERATED_AFTER_IMPORT,
                    retainedFingerprint = "abc123def456",
                    detail = "kind=STALE_GENERATED_AFTER_IMPORT, origin=GENERATED, retained=3",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "ImportKey narrative" &&
                it.body.contains("Matched", ignoreCase = true) &&
                it.body.contains("STALE_GENERATED_AFTER_IMPORT") &&
                it.level == TeeSignalLevel.FAIL
        })
    }

    @Test
    fun `importKey retained narrative unavailable state stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                importKeyRetainedAttestationNarrative = ImportKeyRetainedAttestationNarrativeResult(
                    executed = false,
                    detail = "Keystore2 getKeyEntry metadata unavailable.",
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "ImportKey narrative" &&
                it.body.contains("Unavailable", ignoreCase = true) &&
                it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `importKey unsupported state stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                importKeyRetainedAttestationNarrative = ImportKeyRetainedAttestationNarrativeResult(
                    executed = false,
                    importSupported = false,
                    anomalyKind = ImportKeyRetainedAttestationAnomalyKind.IMPORT_UNSUPPORTED,
                    detail = "ImportKey support gate failed.",
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "ImportKey narrative" &&
                it.body.contains("Unavailable", ignoreCase = true) &&
                it.body.contains("ImportKey support gate failed") &&
                it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `grant isolated-domain full-chain split becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                grantDomainFullChainSplit = GrantDomainFullChainSplitResult(
                    executed = true,
                    available = true,
                    splitDetected = true,
                    ownerChainLength = 3,
                    granteeChainLength = 2,
                    mismatchIndex = 2,
                    granteeUid = 99001,
                    anomalyKind = GrantDomainAnomalyKind.ISOLATED_CHAIN_SPLIT,
                    detail = "Public: clean • Private: matched lengthMismatch owner=3 grantee=2",
                    diagnosticCopyText = "isolated diagnostic\nat com.example.Grant.probe(Grant.kt:1)",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("Grant isolated-domain", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant isolated-domain" &&
                it.level == TeeSignalLevel.FAIL &&
                it.body.contains("Matched", ignoreCase = true) &&
                it.body.contains("kind=ISOLATED_CHAIN_SPLIT") &&
                it.body.contains("mismatchIndex=2") &&
                !it.body.contains("at com.example") &&
                it.hiddenCopyText?.contains("at com.example.Grant.probe") == true
        })
    }

    @Test
    fun `grant isolated-domain key not found after owner chain becomes supplementary review`() {
        val report = reducer.reduce(
            baseArtifacts(
                grantDomainFullChainSplit = GrantDomainFullChainSplitResult(
                    executed = true,
                    available = false,
                    splitDetected = false,
                    ownerChainLength = 3,
                    granteeUid = 99001,
                    anomalyKind = GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
                    detail = "Public: clean • Private: private grant failed: ServiceSpecificException(code 7): No key found by the given alias",
                    diagnosticCopyText = "isolated key-not-found\nat com.example.Grant.keyNotFound(Grant.kt:2)",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("Grant isolated-domain key visibility divergence", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant isolated-domain" &&
                it.level == TeeSignalLevel.FAIL &&
                it.body.contains("Unavailable", ignoreCase = true) &&
                it.body.contains("kind=ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN") &&
                it.body.contains("No key found by the given alias") &&
                !it.body.contains("at com.example") &&
                it.hiddenCopyText?.contains("at com.example.Grant.keyNotFound") == true
        })
    }

    @Test
    fun `grant isolated-domain private readback crash becomes warning supplementary review`() {
        val report = reducer.reduce(
            baseArtifacts(
                grantDomainFullChainSplit = GrantDomainFullChainSplitResult(
                    executed = true,
                    available = false,
                    ownerChainLength = 3,
                    granteeUid = 99001,
                    anomalyKind = GrantDomainAnomalyKind.ISOLATED_PRIVATE_READBACK_CRASH,
                    detail = "Private: isolated readback crashed after grant succeeded.",
                    diagnosticCopyText = """
                        java.lang.reflect.InvocationTargetException
                        Caused by: android.os.ServiceSpecificException: system/security/keystore2/src/service.rs:157: while trying to load key info.

                        Caused by:
                            0: No legacy keys for key descriptor.
                            1: Error::Rc(r#KEY_NOT_FOUND) (code 7)
                    """.trimIndent(),
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertEquals(TeeSignalLevel.WARN, report.supplementaryReviewLevel)
        assertTrue(report.summary.contains("Grant isolated-domain", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant isolated-domain" &&
                it.level == TeeSignalLevel.WARN &&
                it.body.contains("isolated readback crashed", ignoreCase = true) &&
                it.hiddenCopyText?.contains("No legacy keys for key descriptor") == true
        })
    }

    @Test
    fun `grant isolated-domain unavailable state stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                grantDomainFullChainSplit = GrantDomainFullChainSplitResult(
                    executed = false,
                    detail = "Grant-domain full-chain split probe requires Android 16 or newer.",
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant isolated-domain" &&
                it.level == TeeSignalLevel.INFO &&
                it.body.contains("Unavailable", ignoreCase = true)
        })
    }

    @Test
    fun `grant caller binding non grantee readback becomes supplementary danger`() {
        val report = reducer.reduce(
            baseArtifacts(
                syntheticGrantGranteeBlindReadback = SyntheticGrantGranteeBlindReadbackResult(
                    executed = true,
                    available = true,
                    grantCreated = true,
                    granteeUid = 99001,
                    granteeReadSucceeded = true,
                    ownerReplaySucceeded = true,
                    anomalyKind = SyntheticGrantGranteeBlindReadbackAnomalyKind.NON_GRANTEE_READBACK_ALLOWED,
                    detail = "Private: non-grantee owner replay succeeded for isolated grant handle.",
                    diagnosticCopyText = "grant caller binding diagnostic",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertEquals(TeeSignalLevel.FAIL, report.supplementaryReviewLevel)
        assertTrue(report.summary.contains("Grant handle remained readable", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant caller binding" &&
                it.level == TeeSignalLevel.FAIL &&
                it.body.contains("NON_GRANTEE_READBACK_ALLOWED") &&
                it.body.contains("ownerReplay=true") &&
                it.hiddenCopyText == "grant caller binding diagnostic"
        })
    }

    @Test
    fun `grant caller binding rejected owner replay stays clean`() {
        val report = reducer.reduce(
            baseArtifacts(
                syntheticGrantGranteeBlindReadback = SyntheticGrantGranteeBlindReadbackResult(
                    executed = true,
                    available = true,
                    grantCreated = true,
                    granteeUid = 99001,
                    granteeReadSucceeded = true,
                    anomalyKind = SyntheticGrantGranteeBlindReadbackAnomalyKind.NONE,
                    detail = "Private: owner replay rejected with KEY_NOT_FOUND.",
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant caller binding" &&
                it.level == TeeSignalLevel.PASS &&
                it.body.contains("ownerReplay=KEY_NOT_FOUND")
        })
    }

    @Test
    fun `grant access vector missing get info readback becomes supplementary danger`() {
        val report = reducer.reduce(
            baseArtifacts(
                syntheticGrantGetKeyEntryAccessVectorBlindness =
                    SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                        executed = true,
                        available = true,
                        grantCreated = true,
                        granteeUid = 99001,
                        accessVector = 0x100,
                        granteeReadSucceeded = true,
                        anomalyKind =
                            SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.GET_KEY_ENTRY_WITHOUT_GET_INFO_ALLOWED,
                        detail = "Private: grantee getKeyEntry(GRANT) succeeded without GET_INFO.",
                        diagnosticCopyText = "grant access-vector diagnostic",
                    ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertEquals(TeeSignalLevel.FAIL, report.supplementaryReviewLevel)
        assertTrue(report.summary.contains("without GET_INFO", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant access vector" &&
                it.level == TeeSignalLevel.FAIL &&
                it.body.contains("GET_KEY_ENTRY_WITHOUT_GET_INFO_ALLOWED") &&
                it.body.contains("accessVector=256") &&
                it.hiddenCopyText == "grant access-vector diagnostic"
        })
    }

    @Test
    fun `grant access vector permission denied readback stays clean`() {
        val report = reducer.reduce(
            baseArtifacts(
                syntheticGrantGetKeyEntryAccessVectorBlindness =
                    SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                        executed = true,
                        available = true,
                        grantCreated = true,
                        granteeUid = 99001,
                        accessVector = 0x100,
                        anomalyKind = SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.NONE,
                        detail = "Private: grantee getKeyEntry(GRANT) rejected with PERMISSION_DENIED.",
                    ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant access vector" &&
                it.level == TeeSignalLevel.PASS &&
                it.body.contains("granteeRead=PERMISSION_DENIED")
        })
    }

    @Test
    fun `grant self-domain full-chain split becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                grantSelfDomainFullChainSplit = GrantSelfDomainFullChainSplitResult(
                    executed = true,
                    available = true,
                    splitDetected = true,
                    ownerChainLength = 3,
                    grantChainLength = 2,
                    mismatchIndex = 2,
                    grantIdPresent = true,
                    anomalyKind = GrantSelfDomainAnomalyKind.SELF_CHAIN_SPLIT,
                    detail = "Public: clean • Private: matched lengthMismatch owner=3 grantee=2",
                    diagnosticCopyText = "self diagnostic\nat com.example.Grant.selfSplit(Grant.kt:3)",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("Grant self-domain certificate-chain split", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant self-domain" &&
                it.level == TeeSignalLevel.FAIL &&
                it.body.contains("Matched", ignoreCase = true) &&
                it.body.contains("kind=SELF_CHAIN_SPLIT") &&
                it.body.contains("mismatchIndex=2") &&
                !it.body.contains("at com.example") &&
                it.hiddenCopyText?.contains("at com.example.Grant.selfSplit") == true
        })
    }

    @Test
    fun `grant self-domain owner-visible key-not-found state becomes supplementary failure`() {
        val report = reducer.reduce(
            baseArtifacts(
                grantSelfDomainFullChainSplit = GrantSelfDomainFullChainSplitResult(
                    executed = true,
                    ownerChainLength = 4,
                    anomalyKind = GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
                    detail = "Public: clean • Private: private grant failed: ServiceSpecificException(code 7): No key found by the given alias",
                    diagnosticCopyText = "self key-not-found\nat com.example.Grant.selfKeyNotFound(Grant.kt:4)",
                ),
            ),
        )

        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("Grant self-domain key visibility divergence", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant self-domain" &&
                it.level == TeeSignalLevel.FAIL &&
                it.body.contains("Unavailable", ignoreCase = true) &&
                it.body.contains("kind=SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN") &&
                it.body.contains("owner=4") &&
                it.body.contains("No key found by the given alias") &&
                !it.body.contains("at com.example") &&
                it.hiddenCopyText?.contains("at com.example.Grant.selfKeyNotFound") == true
        })
    }

    @Test
    fun `grant self-domain ordinary unavailable state stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                grantSelfDomainFullChainSplit = GrantSelfDomainFullChainSplitResult(
                    executed = false,
                    detail = "private grant failed: IllegalStateException: transient service unavailable",
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant self-domain" &&
                it.level == TeeSignalLevel.INFO &&
                it.body.contains("Unavailable", ignoreCase = true) &&
                it.body.contains("transient service unavailable")
            })
    }

    @Test
    fun `updateSubcomponent stale response persistence becomes supplementary failure`() {
        val report = reducer.reduce(
            baseArtifacts(
                updateSubcomponentStaleResponsePersistence =
                    UpdateSubcomponentStaleResponsePersistenceResult(
                        executed = true,
                        available = true,
                        supportGateClean = true,
                        updateSucceeded = true,
                        staleNarrativeDetected = true,
                        priorChainLength = 3,
                        postChainLength = 2,
                        retainedCertificateCount = 1,
                        postLeafMatchesMarker = false,
                        anomalyKind =
                            UpdateSubcomponentStaleResponseAnomalyKind.STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE,
                        retainedFingerprint = "abc123def456",
                        detail = "kind=STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE, retained=1",
                    ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertEquals(TeeSignalLevel.FAIL, report.supplementaryReviewLevel)
        assertTrue(report.summary.contains("UpdateSubcomponent stale TEE response", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Update persistence" &&
                it.level == TeeSignalLevel.FAIL &&
                it.body.contains("Matched", ignoreCase = true) &&
                it.body.contains("kind=STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE") &&
                it.body.contains("retained=1")
        })
    }

    @Test
    fun `later supplementary failure outranks earlier soter warning`() {
        val report = reducer.reduce(
            baseArtifacts(
                soter = TeeSoterState(
                    serviceReachable = false,
                    keyPrepared = false,
                    signSessionAvailable = false,
                    available = false,
                    damaged = false,
                    abnormalEnvironment = true,
                    summary = "Abnormal Soter environment: Simplified Chinese locale on a likely Soter-supporting device, but PackageManager could not resolve com.tencent.soter.soterserver.",
                ),
                updateSubcomponentStaleResponsePersistence =
                    UpdateSubcomponentStaleResponsePersistenceResult(
                        executed = true,
                        available = true,
                        supportGateClean = true,
                        updateSucceeded = true,
                        staleNarrativeDetected = true,
                        priorChainLength = 3,
                        postChainLength = 2,
                        retainedCertificateCount = 1,
                        postLeafMatchesMarker = false,
                        anomalyKind =
                            UpdateSubcomponentStaleResponseAnomalyKind.STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE,
                        retainedFingerprint = "abc123def456",
                        detail = "kind=STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE, retained=1",
                    ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(2, report.supplementaryIndicatorCount)
        assertEquals(TeeSignalLevel.FAIL, report.supplementaryReviewLevel)
        assertTrue(report.signals.any {
            it.label == "Signals" && it.level == TeeSignalLevel.FAIL
        })
        assertTrue(report.summary.contains("UpdateSubcomponent stale TEE response", ignoreCase = true))
        assertFalse(report.summary.contains("abnormal soter environment", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Soter" && it.level == TeeSignalLevel.WARN
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Update persistence" && it.level == TeeSignalLevel.FAIL
        })
    }

    @Test
    fun `updateSubcomponent stale response clean state stays pass`() {
        val report = reducer.reduce(
            baseArtifacts(
                updateSubcomponentStaleResponsePersistence =
                    UpdateSubcomponentStaleResponsePersistenceResult(
                        executed = true,
                        available = true,
                        supportGateClean = true,
                        updateSucceeded = true,
                        staleNarrativeDetected = false,
                        priorChainLength = 3,
                        postChainLength = 1,
                        postLeafMatchesMarker = true,
                        anomalyKind = UpdateSubcomponentStaleResponseAnomalyKind.NONE,
                        detail = "kind=NONE, marker leaf returned.",
                    ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Update persistence" &&
                it.level == TeeSignalLevel.PASS &&
                it.body.contains("Clean", ignoreCase = true) &&
                it.body.contains("kind=NONE")
        })
    }

    @Test
    fun `updateSubcomponent stale response unavailable state stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                updateSubcomponentStaleResponsePersistence =
                    UpdateSubcomponentStaleResponsePersistenceResult(
                        executed = false,
                        supportGateClean = false,
                        anomalyKind = UpdateSubcomponentStaleResponseAnomalyKind.UPDATE_SUBCOMPONENT_UNOBSERVABLE,
                        detail = "UpdateSubcomponent support gate failed.",
                    ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Update persistence" &&
                it.level == TeeSignalLevel.INFO &&
                it.body.contains("Unavailable", ignoreCase = true) &&
                it.body.contains("kind=UPDATE_SUBCOMPONENT_UNOBSERVABLE")
        })
    }

    @Test
    fun `list entries mismatch becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                listEntriesConsistency = ListEntriesConsistencyResult(
                    executed = true,
                    containsAlias = true,
                    listedInAliases = false,
                    inconsistent = true,
                    detail = "containsAlias=true, listedInAliases=false",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.summary.contains("containsAlias()/aliases()", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "listEntries" && it.body.contains("mismatch", ignoreCase = true)
        })
    }

    @Test
    fun `binder chain divergence becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                binderChainConsistency = BinderChainConsistencyResult(
                    executed = true,
                    hookInstalled = true,
                    keystoreChainAvailable = true,
                    binderMaterialAvailable = true,
                    activeProbeSecondCycleSucceeded = true,
                    leafMatches = true,
                    chainMatches = false,
                    keystoreChainLength = 3,
                    binderChainLength = 2,
                    detail = "leafMatches=true, chainMatches=false",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Binder chain" && it.body.contains("diverged", ignoreCase = true)
        })
    }

    @Test
    fun `binder hook bootstrap failure becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                binderHookBootstrap = BinderHookBootstrapResult(
                    executed = true,
                    hookInstalled = false,
                    detail = "bootstrap failed",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Binder hook" && it.body.contains("failed", ignoreCase = true)
        })
    }

    @Test
    fun `binder chain delete entry residue is surfaced in checks`() {
        val report = reducer.reduce(
            baseArtifacts(
                binderChainConsistency = BinderChainConsistencyResult(
                    executed = true,
                    hookInstalled = true,
                    keystoreChainAvailable = true,
                    binderMaterialAvailable = true,
                    activeProbeSecondCycleSucceeded = true,
                    chainMatches = true,
                    deleteEntryRemovedAlias = false,
                    detail = "deleteEntryRemovedAlias=false",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Binder chain" && it.body.contains("deleteEntry left alias present", ignoreCase = true)
        })
    }

    @Test
    fun `binder chain repeated active probe failure is surfaced in checks`() {
        val report = reducer.reduce(
            baseArtifacts(
                binderChainConsistency = BinderChainConsistencyResult(
                    executed = true,
                    hookInstalled = true,
                    keystoreChainAvailable = true,
                    binderMaterialAvailable = true,
                    activeProbeRepeated = true,
                    activeProbeSecondCycleSucceeded = false,
                    detail = "cycle2 failed",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Binder chain" && it.body.contains("Repeated active probe failed", ignoreCase = true)
        })
    }

    @Test
    fun `binder chain repeated active probe failure keeps cycle detail`() {
        val report = reducer.reduce(
            baseArtifacts(
                binderChainConsistency = BinderChainConsistencyResult(
                    executed = true,
                    hookInstalled = true,
                    keystoreChainAvailable = true,
                    binderMaterialAvailable = false,
                    activeProbeRepeated = true,
                    activeProbeSecondCycleSucceeded = false,
                    detail = "cycle2 binder material unavailable: Neither getKeyEntry nor generateKey exposed certificate material for the probe alias.",
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Binder chain" &&
                it.body.contains("Repeated active probe failed", ignoreCase = true) &&
                it.body.contains("binder material unavailable", ignoreCase = true)
        })
    }

    @Test
    fun `patch mode divergence becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                binderPatchMode = BinderPatchModeResult(
                    executed = true,
                    hookInstalled = true,
                    generateMaterialAvailable = true,
                    keyEntryMaterialAvailable = true,
                    leafDiffers = true,
                    detail = "leafDiffers=true",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Patch mode" && it.body.contains("Leaf differed", ignoreCase = true)
        })
    }

    @Test
    fun `legacy keystore divergence stays supplementary without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                legacyKeystorePath = LegacyKeystorePathResult(
                    executed = true,
                    hookInstalled = true,
                    userCertCaptured = true,
                    caCertCaptured = true,
                    legacyMaterialAvailable = true,
                    chainMatches = false,
                    legacyChainLength = 2,
                    detail = "legacy mismatch",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Legacy keystore" && it.body.contains("diverged", ignoreCase = true)
        })
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

    @Test
    fun `native got hook becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                native = NativeTeeSnapshot(
                    trickyStoreDetected = true,
                    gotHookDetected = true,
                    trickyStoreMethods = listOf("GOT_HOOK"),
                    trickyStoreDetails = "got hook",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(2, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("GOT", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Native" && it.body.contains("GOT hook")
        })
    }

    @Test
    fun `native honeypot detail exposes timer source fallback and affinity diagnostics`() {
        val report = reducer.reduce(
            baseArtifacts(
                native = NativeTeeSnapshot(
                    trickyStoreDetected = true,
                    honeypotDetected = true,
                    trickyStoreMethods = listOf("HONEYPOT"),
                    trickyStoreDetails = "Keystore-style binder honeypot triggered on 2/3 timing runs.",
                    trickyStoreTimerSource = "arm64_cntvct",
                    trickyStoreTimerFallbackReason = "counter self-check failed once; retried with monotonic clock",
                    trickyStoreAffinityStatus = "bound_cpu0",
                    trickyStoreTimingRunCount = 3,
                    trickyStoreTimingSuspiciousRunCount = 2,
                    trickyStoreTimingMedianGapNs = 18420L,
                    trickyStoreTimingGapMadNs = 910L,
                    trickyStoreTimingMedianNoiseFloorNs = 10000L,
                    trickyStoreTimingMedianRatioPercent = 167,
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Native" &&
                    it.body.contains("Honeypot") &&
                    it.body.contains("arm64_cntvct") &&
                    it.body.contains("bound_cpu0") &&
                    it.body.contains("2/3 suspicious runs") &&
                    it.body.contains("18.4us") &&
                    it.body.contains("0.9us") &&
                    it.body.contains("10.0us") &&
                    it.body.contains("1.67x") &&
                    it.body.contains("Keystore-style binder honeypot triggered on 2/3 timing runs.")
        })
    }

    @Test
    fun `native summary still exposes timing comparison when honeypot stays within bounds`() {
        val report = reducer.reduce(
            baseArtifacts(
                native = NativeTeeSnapshot(
                    trickyStoreDetected = false,
                    honeypotDetected = false,
                    trickyStoreDetails = "Keystore-style binder honeypot timing stayed within normal bounds across redundant backends. libc=41234ns, syscall=25011ns, asm=24890ns timer=arm64_cntvct, affinity=bound_cpu0.",
                    trickyStoreTimerSource = "arm64_cntvct",
                    trickyStoreAffinityStatus = "bound_cpu0",
                    trickyStoreTimingRunCount = 3,
                    trickyStoreTimingSuspiciousRunCount = 0,
                    trickyStoreTimingMedianGapNs = 16342L,
                    trickyStoreTimingGapMadNs = 850L,
                    trickyStoreTimingMedianNoiseFloorNs = 10000L,
                    trickyStoreTimingMedianRatioPercent = 166,
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Native" &&
                    it.body.contains("41234ns") &&
                    it.body.contains("25011ns") &&
                    it.body.contains("24890ns") &&
                    it.body.contains("0/3 suspicious runs") &&
                    it.body.contains("16.3us") &&
                    it.body.contains("0.9us") &&
                    it.body.contains("10.0us") &&
                    it.body.contains("1.66x") &&
                    it.body.contains("arm64_cntvct") &&
                    it.body.contains("bound_cpu0")
        })
    }

    @Test
    fun `timing probe warning stays in checks without creating supplementary review`() {
        val report = reducer.reduce(
            baseArtifacts(
                timing = TimingAnomalyResult(
                    suspicious = true,
                    medianMicros = 299,
                    detail = "Timing side-channel diff 0.299ms stayed below the 0.3ms positive threshold.",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.signals.any {
            it.label == "Signals" &&
                    it.value == "0 policy hard • 0 policy review • 0 local" &&
                    it.level == TeeSignalLevel.PASS
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing" &&
                    it.body == "Fast/steady • 299us" &&
                    it.level == TeeSignalLevel.WARN
        })
        assertEquals("Attestation, trust path, and revocation checks line up.", report.summary)
    }

    @Test
    fun `timing probe equality threshold remains non positive in reducer output`() {
        val report = reducer.reduce(
            baseArtifacts(
                timing = TimingAnomalyResult(
                    suspicious = false,
                    medianMicros = 300,
                    detail = "Timing side-channel diff 0.3ms matched the threshold and remained non-positive.",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing" &&
                    it.body == "Median 300us" &&
                    it.level == TeeSignalLevel.INFO
        })
        assertTrue(report.signals.any {
            it.label == "Signals" &&
                    it.value == "0 policy hard • 0 policy review • 0 local" &&
                    it.level == TeeSignalLevel.PASS
        })
    }

    @Test
    fun `timing side-channel positive result becomes supplementary review and exposes metrics`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = true,
                    suspicious = true,
                    sampleCount = 18,
                    attemptedPairCount = 20,
                    successfulPairCount = 20,
                    failedPairCount = 0,
                    filteredOutlierCount = 2,
                    ratioEligible = true,
                    warmupCount = 5,
                    avgAttestedMillis = 0.612,
                    avgNonAttestedMillis = 0.400,
                    diffMillis = 0.212,
                    detail = "register timer source; avgAttested=0.612ms, avgNonAttested=0.400ms, diff=0.212ms",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("timing side-channel", ignoreCase = true))
        assertTrue(report.summary.contains("supplementary", ignoreCase = true))
        assertTrue(report.summary.contains("ratio 1.53x exceeded 1.1x", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Register timer") &&
                    it.body.contains("attested 0.612ms") &&
                    it.body.contains("non-attested 0.400ms") &&
                    it.body.contains("diff 0.212ms") &&
                    it.body.contains("failedPairs=0/20") &&
                    it.body.contains("outlierFiltered=2/20") &&
                    it.body.contains("samples=18") &&
                    it.body.contains("ratio 1.530x") &&
                    it.body.contains("threshold > 1.1x") &&
                    it.level == TeeSignalLevel.WARN
        })
    }

    @Test
    fun `timing side-channel insufficient samples skip ratio without supplementary review`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = true,
                    suspicious = true,
                    sampleCount = 299,
                    attemptedPairCount = 500,
                    successfulPairCount = 320,
                    failedPairCount = 180,
                    filteredOutlierCount = 21,
                    ratioEligible = false,
                    ratioSkipReason = "insufficientSamples=299/300",
                    warmupCount = 5,
                    avgAttestedMillis = 0.612,
                    avgNonAttestedMillis = 0.400,
                    diffMillis = 0.212,
                    detail = "register timer source; insufficientSamples=299/300",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("ratio skipped") &&
                    it.body.contains("failedPairs=180/500") &&
                    it.body.contains("outlierFiltered=21/320") &&
                    it.body.contains("samples=299") &&
                    it.body.contains("insufficientSamples=299/300") &&
                    it.body.contains("Ratio skipped") &&
                    !it.body.contains("Positive") &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `timing side-channel invalid ratio stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = true,
                    suspicious = false,
                    sampleCount = 20,
                    warmupCount = 5,
                    avgAttestedMillis = 0.200,
                    avgNonAttestedMillis = 0.000,
                    diffMillis = 0.200,
                    detail = "fallback timer path; avgAttested=0.200ms, avgNonAttested=0.000ms, diff=0.200ms",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Fallback timer") &&
                    it.body.contains("diff 0.200ms") &&
                    it.body.contains("ratio n/a") &&
                    it.body.contains("Not positive") &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `timing side-channel negative threshold breach becomes supplementary review with fallback wording`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = true,
                    suspicious = true,
                    sampleCount = 20,
                    warmupCount = 5,
                    avgAttestedMillis = 0.100,
                    avgNonAttestedMillis = 0.450,
                    diffMillis = -0.350,
                    detail = "fallback timer path; avgAttested=0.100ms, avgNonAttested=0.450ms, diff=-0.350ms",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("Fallback timer timing side-channel stayed supplementary"))
        assertTrue(report.summary.contains("ratio 4.50x exceeded 1.1x"))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Fallback timer") &&
                    it.body.contains("diff -0.350ms") &&
                    it.body.contains("ratio 4.500x") &&
                    it.body.contains("threshold > 1.1x") &&
                    it.level == TeeSignalLevel.WARN
        })
    }

    @Test
    fun `timing side-channel degraded result still shows timer affinity and reason`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = false,
                    suspicious = false,
                    sampleCount = 500,
                    warmupCount = 5,
                    source = "keystore2_getKeyEntry_binder",
                    timerSource = "arm64_cntvct",
                    affinity = "bound_cpu0",
                    failureReason = "Keystore2 getKeyEntry transact returned false",
                    stackCopyPayload = "phase=warmup.attested[0]\nsummary=ServiceSpecificException(code 7)",
                    detail = "measurement unavailable after binder transact failure",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Register timer") &&
                    it.body.contains("bound_cpu0") &&
                    it.body.contains("Measurement unavailable") &&
                    it.body.contains("reason Keystore2 getKeyEntry transact returned false") &&
                    it.level == TeeSignalLevel.INFO
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                it.hiddenCopyText?.contains("phase=warmup.attested[0]") == true
        })
    }

    @Test
    fun `timing side-channel skipped getKeyEntry stack marks tricky-store patch mode as fail`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = false,
                    sampleCount = 0,
                    warmupCount = 5,
                    timerSource = "arm64_cntvct",
                    affinity = "bound_cpu0",
                    failureReason = "cleanup failed",
                    stackCopyPayload = """
                        phase=warmup.attested[0]
                        summary=ServiceSpecificException(code 7)

                        Caused by: android.os.ServiceSpecificException (code 7)
                        	at android.os.Parcel.createException(Parcel.java:3353)
                        	at android.os.Parcel.readException(Parcel.java:3336)
                        	at ${'$'}Proxy5.getKeyEntry(Unknown Source)
                    """.trimIndent(),
                    detail = "measurement unavailable after getKeyEntry failure",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("Detected malicious-module fingerprint during timing skip", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Detected malicious-module fingerprint") &&
                    it.body.contains("Register timer") &&
                    it.body.contains("bound_cpu0") &&
                    it.level == TeeSignalLevel.FAIL
        })
        assertFalse(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" && it.body.contains("Measurement unavailable")
        })
    }

    @Test
    fun `timing side-channel skipped generateKey and deleteKey stack marks tee simulator patch mode as fail`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = false,
                    sampleCount = 0,
                    warmupCount = 5,
                    timerSource = "clock_monotonic",
                    affinity = "not_requested",
                    failureReason = "security level generateKey failed",
                    stackCopyPayload = """
                        phase=securityLevel.generateKey
                        summary=ServiceSpecificException(code -49)

                        android.os.ServiceSpecificException (code -49)
                        	at android.os.Parcel.createExceptionOrNull(Parcel.java:3383)
                        	at android.os.Parcel.createException(Parcel.java:3353)
                        	at android.os.Parcel.readException(Parcel.java:3336)
                        	at ${'$'}Proxy7.generateKey(Unknown Source)

                        Caused by:
                            0: Legacy database is empty.
                            1: Error::Rc(r#KEY_NOT_FOUND) (code 7)
                        	at ${'$'}Proxy5.deleteKey(Unknown Source)
                    """.trimIndent(),
                    detail = "measurement unavailable after legacy database failure",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("Detected malicious-module fingerprint during timing skip", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Detected malicious-module fingerprint") &&
                    it.body.contains("Fallback timer") &&
                    it.body.contains("not_requested") &&
                    it.level == TeeSignalLevel.FAIL
        })
        assertFalse(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" && it.body.contains("Measurement unavailable")
        })
    }

    @Test
    fun `timing side-channel skipped legacy database code 75 stack marks tee simulator patch and generate mode as fail`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = false,
                    sampleCount = 0,
                    warmupCount = 5,
                    timerSource = "clock_monotonic",
                    affinity = "not_requested",
                    failureReason = "security level generateKey failed",
                    stackCopyPayload = """
                        phase=securityLevel.generateKey
                        summary=ServiceSpecificException(code -75)

                        android.os.ServiceSpecificException (code -75)
                        	at android.os.Parcel.createExceptionOrNull(Parcel.java:3270)
                        	at android.os.Parcel.createException(Parcel.java:3240)
                        	at android.os.Parcel.readException(Parcel.java:3223)

                        Caused by:
                            0: Legacy database is empty.
                            1: Error::Rc(r#KEY_NOT_FOUND) (code 7)
                    """.trimIndent(),
                    detail = "measurement unavailable after legacy database failure",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(2, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("Detected malicious-module fingerprint during timing skip", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Detected malicious-module fingerprint") &&
                    it.body.contains("Fallback timer") &&
                    it.body.contains("not_requested") &&
                    it.level == TeeSignalLevel.FAIL
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "TEE Simulator generate-mode fingerprint" &&
                    it.body.contains("Matched TEE Simulator generate-mode fingerprint.") &&
                    it.level == TeeSignalLevel.FAIL &&
                    it.hiddenCopyText == null
        })
        assertFalse(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" && it.body.contains("Measurement unavailable")
        })
    }

    @Test
    fun `timing side-channel skipped parcel trio falls back to warning private binder exception`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = false,
                    sampleCount = 0,
                    warmupCount = 5,
                    timerSource = "clock_monotonic",
                    affinity = "not_requested",
                    failureReason = "security level probe failed",
                    stackCopyPayload = """
                        phase=securityLevel.generateKey
                        summary=ServiceSpecificException(code -1)

                        android.os.ServiceSpecificException (code -1)
                        	at android.os.Parcel.createExceptionOrNull(Parcel.java:3270)
                        	at android.os.Parcel.createException(Parcel.java:3240)
                        	at android.os.Parcel.readException(Parcel.java:3223)
                    """.trimIndent(),
                    detail = "measurement unavailable after generic parcel failure",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("private binder exception during timing skip", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Captured private binder exception during timing skip") &&
                    it.body.contains("Fallback timer") &&
                    it.body.contains("not_requested") &&
                    it.level == TeeSignalLevel.WARN
        })
        assertFalse(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" && it.body.contains("Measurement unavailable")
        })
    }

    @Test
    fun `timing side-channel negative measured result still shows timer and affinity`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = true,
                    suspicious = false,
                    sampleCount = 1000,
                    warmupCount = 5,
                    avgAttestedMillis = 0.280,
                    avgNonAttestedMillis = 0.120,
                    diffMillis = 0.160,
                    source = "keystore2_getKeyEntry_binder",
                    timerSource = "arm64_cntvct",
                    affinity = "bound_cpu0",
                    detail = "stable negative measurement",
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Register timer") &&
                    it.body.contains("bound_cpu0") &&
                    it.body.contains("attested 0.280ms") &&
                    it.body.contains("non-attested 0.120ms") &&
                    it.body.contains("diff 0.160ms") &&
                    it.body.contains("Not positive") &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `timing side-channel partial samples still show available timing context`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = true,
                    suspicious = false,
                    sampleCount = 1000,
                    warmupCount = 5,
                    avgAttestedMillis = 0.310,
                    avgNonAttestedMillis = null,
                    diffMillis = null,
                    source = "keystore2_getKeyEntry_binder",
                    timerSource = "arm64_cntvct",
                    affinity = "bound_cpu0",
                    failureReason = "non-attested path unavailable",
                    detail = "partial timing measurement",
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Register timer") &&
                    it.body.contains("bound_cpu0") &&
                    it.body.contains("attested 0.310ms") &&
                    it.body.contains("non-attested n/a") &&
                    it.body.contains("diff n/a") &&
                    it.body.contains("Not positive") &&
                    it.body.contains("reason non-attested path unavailable") &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `native syscall mismatch only stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                native = NativeTeeSnapshot(
                    syscallMismatchDetected = true,
                    trickyStoreMethods = listOf("SYSCALL_MISMATCH"),
                    trickyStoreDetails = "sys mismatch",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Indicators" && it.body == "0 policy hard • 0 policy review • 0 local"
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Native" &&
                    it.body.contains("Syscall mismatch") &&
                    it.body.contains("vendor binder/libc", ignoreCase = true) &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `device ids omitted from attestation are not shown as unavailable`() {
        val report = reducer.reduce(
            baseArtifacts(
                deviceInfo = AttestedDeviceInfo(),
                idAttestation = IdAttestationResult(
                    mismatches = emptyList(),
                    unavailableFields = listOf(
                        "brand",
                        "device",
                        "product",
                        "manufacturer",
                        "model"
                    ),
                    detail = "Attestation did not expose any comparable device identifiers.",
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Attestation" }.items.any {
            it.title == "Device IDs" && it.body == "Not included in attestation"
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "ID attestation" && it.body == "No comparable IDs exposed"
        })
    }

    @Test
    fun `graded oversized challenge lists accepted sizes`() {
        val report = reducer.reduce(
            baseArtifacts(
                oversizedChallenge = OversizedChallengeResult(
                    acceptedOversizedChallenge = true,
                    acceptedSizes = listOf(256, 512, 4096),
                    attemptedSizes = listOf(256, 512, 4096),
                    detail = "Attestation accepted oversized challenge sizes: 256B, 512B, 4096B.",
                ),
            ),
        )

        assertEquals(TeeVerdict.SUSPICIOUS, report.verdict)
        assertTrue(report.summary.contains("256B"))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Oversized challenge" && it.body.contains("256B") && it.body.contains("4096B")
        })
    }

    @Test
    fun `dual algorithm difference no longer drives verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                dualAlgorithm = DualAlgorithmChainResult(
                    mismatchDetected = true,
                    detail = "rsa/ec differ",
                    trustRootMismatch = true,
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Dual algorithm" &&
                    it.body.contains("difference observed") &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `strongbox heuristic warning stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                strongBox = StrongBoxBehaviorResult(
                    requested = true,
                    advertised = true,
                    available = true,
                    warnings = listOf("StrongBox accepted RSA-4096, which is atypical for current hardware-backed implementations."),
                    detail = "note",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "StrongBox" &&
                    it.body.contains("RSA-4096") &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `software backed aes gcm key becomes local review signal`() {
        val report = reducer.reduce(
            baseArtifacts(
                aesGcm = AesGcmRoundTripResult(
                    executed = true,
                    roundTripSucceeded = true,
                    keyInfoLevel = "Software",
                    insideSecureHardware = false,
                    detail = "software",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("software-backed", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "AES-GCM" &&
                    it.body.contains("software-backed", ignoreCase = true) &&
                    it.level == TeeSignalLevel.WARN
        })
    }

    @Test
    fun `aes gcm roundtrip failure becomes supplementary fail signal`() {
        val report = reducer.reduce(
            baseArtifacts(
                aesGcm = AesGcmRoundTripResult(
                    executed = true,
                    roundTripSucceeded = false,
                    keyInfoLevel = "TEE",
                    insideSecureHardware = true,
                    detail = "failed",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("AES-GCM", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "AES-GCM" &&
                    it.body.contains("Round-trip failed") &&
                    it.level == TeeSignalLevel.FAIL
        })
    }

    @Test
    fun `skipped aes gcm probe remains informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                aesGcm = AesGcmRoundTripResult(
                    executed = false,
                    detail = "AES-GCM round-trip probe skipped.",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "AES-GCM" &&
                    it.body == "Skipped" &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `unknown strongbox attestation tier no longer creates supplementary review`() {
        val report = reducer.reduce(
            baseArtifacts(
                tier = TeeTier.TEE,
                strongBox = StrongBoxBehaviorResult(
                    requested = true,
                    advertised = true,
                    available = true,
                    attestationTier = TeeTier.UNKNOWN,
                    keyInfoLevel = "StrongBox",
                    warnings = listOf(
                        "StrongBox key generation succeeded, but dedicated attestation did not expose a tier.",
                    ),
                    detail = "unknown tier",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(TeeTier.STRONGBOX, report.tier)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertEquals("Attestation, trust path, and revocation checks line up.", report.summary)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "StrongBox" &&
                    it.body.contains("did not expose a tier") &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `confirmed strongbox upgrades displayed tier from tee`() {
        val report = reducer.reduce(
            baseArtifacts(
                tier = TeeTier.TEE,
                strongBox = StrongBoxBehaviorResult(
                    requested = true,
                    advertised = true,
                    available = true,
                    attestationTier = TeeTier.STRONGBOX,
                    keyInfoLevel = "StrongBox",
                    detail = "confirmed",
                ),
            ),
        )

        assertEquals(TeeTier.STRONGBOX, report.tier)
        assertTrue(report.sections.single { it.title == "Attestation" }.items.any {
            it.title == "Tier" &&
                    it.body.contains("StrongBox") &&
                    it.body.contains("attest TEE")
        })
    }

    @Test
    fun `software tier is not upgraded by strongbox side probe`() {
        val report = reducer.reduce(
            baseArtifacts(
                tier = TeeTier.SOFTWARE,
                strongBox = StrongBoxBehaviorResult(
                    requested = true,
                    advertised = true,
                    available = true,
                    attestationTier = TeeTier.STRONGBOX,
                    keyInfoLevel = "StrongBox",
                    detail = "confirmed",
                ),
            ),
        )

        assertEquals(TeeTier.SOFTWARE, report.tier)
        assertTrue(report.sections.single { it.title == "Attestation" }.items.any {
            it.title == "Tier" &&
                    it.body.startsWith("Software") &&
                    it.body.contains("sb attest StrongBox")
        })
    }

    @Test
    fun `disabled online crl refresh still reports built in snapshot`() {
        val report = reducer.reduce(
            baseArtifacts(
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.SKIPPED,
                    summary = "Built-in revocation snapshot is active; online refresh is disabled in Settings.",
                    cacheEntries = 1,
                    usedCache = true,
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Trust" }.items.any {
            it.title == "CRL" && it.body.contains("Built-in snapshot")
        })
        assertTrue(report.signals.any { it.label == "CRL" && it.value == "Built-in" })
    }

    @Test
    fun `local mass abuse revocation is warning not tampered`() {
        val report = reducer.reduce(
            baseArtifacts(
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.SKIPPED,
                    summary = "Built-in revocation snapshot is active; online refresh is disabled in Settings.",
                    cacheEntries = 1,
                    usedCache = true,
                ),
                crlRevokedCertificates = listOf(
                    RevokedCertificate(
                        serial = "8616ef30679ed43cc2b43e3c97a2319e / 178194732304493...",
                        reason = "MASS_ABUSE",
                        evidenceKind = RevokedCertificateEvidenceKind.LOCAL_MASS_ABUSE,
                    )
                ),
            ),
        )

        assertEquals(TeeVerdict.SUSPICIOUS, report.verdict)
        assertTrue(report.summary.contains("mass abuse", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Trust" }.items.any {
            it.title == "CRL" &&
                    it.body.contains("mass abuse", ignoreCase = true) &&
                    it.level == TeeSignalLevel.WARN
        })
        assertTrue(report.signals.any {
            it.label == "CRL" && it.value == "Mass abuse" && it.level == TeeSignalLevel.WARN
        })
    }

    @Test
    fun `standard crl revocation remains tampered`() {
        val report = reducer.reduce(
            baseArtifacts(
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.ACTIVE,
                    summary = "Online revocation data refreshed successfully.",
                ),
                crlRevokedCertificates = listOf(
                    RevokedCertificate(
                        serial = "8616ef30679ed43cc2b43e3c97a2319e / 178194732304493...",
                        reason = "KEY_COMPROMISE",
                    )
                ),
            ),
        )

        assertEquals(TeeVerdict.TAMPERED, report.verdict)
        assertTrue(report.sections.single { it.title == "Trust" }.items.any {
            it.title == "CRL" &&
                    it.body.contains("revoked", ignoreCase = true) &&
                    it.level == TeeSignalLevel.FAIL
        })
        assertTrue(report.signals.any {
            it.label == "CRL" && it.value == "Revoked" && it.level == TeeSignalLevel.FAIL
        })
    }

    @Test
    fun `refresh failed crl state is surfaced as degraded`() {
        val report = reducer.reduce(
            baseArtifacts(
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.ERROR,
                    summary = "Online CRL refresh failed; built-in revocation snapshot was used.",
                    detail = "CRL refresh timed out.",
                    cacheEntries = 1,
                    usedCache = true,
                    usingCacheFallback = true,
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Trust" }.items.any {
            it.title == "CRL" &&
                    it.body.contains("Built-in snapshot") &&
                    it.body.contains("timed out")
        })
        assertTrue(report.signals.any { it.label == "CRL" && it.value == "Built-in" && it.level == TeeSignalLevel.WARN })
    }

    @Test
    fun `provisioned rkp does not stay green when local chain fails`() {
        val report = reducer.reduce(
            baseArtifacts(
                trust = CertificateTrustResult(
                    trustRoot = TeeTrustRoot.GOOGLE,
                    chainLength = 3,
                    chainSignatureValid = false,
                    googleRootMatched = true,
                ),
                rkp = TeeRkpState(
                    provisioned = true,
                    serverSigned = true,
                    validityDays = 30,
                ),
            ),
        )

        assertEquals(TeeSignalLevel.FAIL, report.localTrustChainLevel)
        assertEquals(
            TeeSignalLevel.FAIL,
            report.sections.single { it.title == "Trust" }.items.single { it.title == "RKP" }.level
        )
        assertTrue(report.trustSummary.contains("invalid local chain"))
    }

    @Test
    fun `rkp issuance count no longer creates custom soft anomaly`() {
        val report = reducer.reduce(
            baseArtifacts(
                rkp = TeeRkpState(
                    provisioned = true,
                    serverSigned = true,
                    abuseLevel = TeeSignalLevel.INFO,
                    abuseSummary = "Provisioning info reported approximately 1200 short-lived certificates in the last 30 days.",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.none { section ->
            section.items.any { it.title == "RKP issuance" }
        })
    }

    @Test
    fun `soter skip stays local warning without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                soter = TeeSoterState(
                    serviceReachable = false,
                    keyPrepared = false,
                    signSessionAvailable = false,
                    available = false,
                    damaged = false,
                    summary = "Soter Treble service was not reachable; probe skipped.",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertEquals("Attestation, trust path, and revocation checks line up.", report.summary)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Soter" &&
                    it.body.contains("probe skipped", ignoreCase = true) &&
                    it.level == TeeSignalLevel.WARN
        })
    }

    @Test
    fun `soter key or signing failure becomes tampered verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                soter = TeeSoterState(
                    serviceReachable = true,
                    keyPrepared = false,
                    signSessionAvailable = false,
                    available = false,
                    damaged = true,
                    summary = "Soter key preparation failed after the Treble service became reachable.",
                ),
            ),
        )

        assertEquals(TeeVerdict.TAMPERED, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Soter" &&
                    it.body.contains("Soter key preparation failed", ignoreCase = true) &&
                    it.level == TeeSignalLevel.FAIL
        })
        assertTrue(report.signals.any {
            it.label == "Signals" &&
                    it.value.contains("1 policy hard")
        })
    }

    @Test
    fun `abnormal soter environment becomes local warning and yellows card state`() {
        val report = reducer.reduce(
            baseArtifacts(
                soter = TeeSoterState(
                    serviceReachable = false,
                    keyPrepared = false,
                    signSessionAvailable = false,
                    available = false,
                    damaged = false,
                    abnormalEnvironment = true,
                    summary = "Abnormal Soter environment: Simplified Chinese locale on a likely Soter-supporting device, but PackageManager could not resolve com.tencent.soter.soterserver.",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertEquals(TeeSignalLevel.WARN, report.supplementaryReviewLevel)
        assertTrue(report.summary.contains("abnormal soter environment", ignoreCase = true))
        assertTrue(report.signals.any {
            it.label == "Signals" &&
                    it.value.contains("1 local")
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Soter" &&
                    it.body.contains("abnormal soter environment", ignoreCase = true) &&
                    it.level == TeeSignalLevel.WARN
        })
    }

    private fun baseArtifacts(
        tier: TeeTier = TeeTier.TEE,
        chainStructure: ChainStructureResult = ChainStructureResult(
            chainLength = 3,
            attestationExtensionCount = 1,
            trustedAttestationIndex = 1,
            detail = "base",
        ),
        keystore2Hook: Keystore2HookResult = Keystore2HookResult(
            available = true,
            nativeStyleResponse = true,
            detail = "native",
        ),
        deviceInfo: AttestedDeviceInfo = AttestedDeviceInfo(brand = "duck", device = "duck"),
        idAttestation: IdAttestationResult = IdAttestationResult(
            mismatches = emptyList(),
            unavailableFields = emptyList(),
            detail = "ok",
        ),
        oversizedChallenge: OversizedChallengeResult = OversizedChallengeResult(
            acceptedOversizedChallenge = false,
            acceptedSizes = emptyList(),
            attemptedSizes = listOf(256, 512, 4096),
            detail = "ok",
        ),
        native: NativeTeeSnapshot = NativeTeeSnapshot(
            trickyStoreDetails = "clean",
        ),
        dualAlgorithm: DualAlgorithmChainResult = DualAlgorithmChainResult(
            mismatchDetected = false,
            detail = "ok",
        ),
        aesGcm: AesGcmRoundTripResult = AesGcmRoundTripResult(
            executed = true,
            roundTripSucceeded = true,
            keyInfoLevel = "TEE",
            insideSecureHardware = true,
            encryptMicros = 1600,
            decryptMicros = 1700,
            detail = "ok",
        ),
        timing: TimingAnomalyResult = TimingAnomalyResult(
            suspicious = false,
            medianMicros = 1800,
            detail = "ok",
        ),
        timingSideChannel: TimingSideChannelResult = TimingSideChannelResult(
            probeRan = false,
            measurementAvailable = false,
            timerSource = "unknown",
            affinity = "not_requested",
            failureReason = "skipped",
            detail = "skipped",
        ),
        strongBox: StrongBoxBehaviorResult = StrongBoxBehaviorResult(
            requested = false,
            advertised = false,
            available = false,
            detail = "skipped",
        ),
        bootConsistency: BootConsistencyResult = BootConsistencyResult(
            runtimePropsAvailable = true,
            runtimeVbmetaDigest = "12345678",
            detail = "Attested verifiedBootHash matched ro.boot.vbmeta.digest.",
        ),
        networkState: TeeNetworkState = TeeNetworkState(
            mode = TeeNetworkMode.INACTIVE,
            summary = "Offline-only verification",
        ),
        crlRevokedCertificates: List<RevokedCertificate> = emptyList(),
        trust: CertificateTrustResult = CertificateTrustResult(
            trustRoot = TeeTrustRoot.GOOGLE,
            chainLength = 3,
            chainSignatureValid = true,
            googleRootMatched = true,
        ),
        rkp: TeeRkpState = TeeRkpState(),
        soter: TeeSoterState = TeeSoterState(),
        legacyKeystorePath: LegacyKeystorePathResult = LegacyKeystorePathResult(
            executed = false,
            detail = "skipped",
        ),
        listEntriesConsistency: ListEntriesConsistencyResult = ListEntriesConsistencyResult(
            executed = false,
            detail = "skipped",
        ),
        listEntriesBatched: ListEntriesBatchedResult = ListEntriesBatchedResult(
            executed = false,
            detail = "skipped",
        ),
        generateModeParcelFingerprint: Keystore2GenerateModeParcelFingerprintResult = Keystore2GenerateModeParcelFingerprintResult(
            executed = false,
            detail = "skipped",
        ),
        importKeyRetainedAttestationNarrative: ImportKeyRetainedAttestationNarrativeResult =
            ImportKeyRetainedAttestationNarrativeResult(
                executed = false,
                detail = "skipped",
            ),
        grantDomainFullChainSplit: GrantDomainFullChainSplitResult = GrantDomainFullChainSplitResult(
            detail = "skipped",
        ),
        syntheticGrantGranteeBlindReadback: SyntheticGrantGranteeBlindReadbackResult =
            SyntheticGrantGranteeBlindReadbackResult(
                detail = "skipped",
            ),
        syntheticGrantGetKeyEntryAccessVectorBlindness: SyntheticGrantGetKeyEntryAccessVectorBlindnessResult =
            SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                detail = "skipped",
            ),
        grantSelfDomainFullChainSplit: GrantSelfDomainFullChainSplitResult = GrantSelfDomainFullChainSplitResult(
            detail = "skipped",
        ),
        keyMetadataSemantics: KeyMetadataSemanticsResult = KeyMetadataSemanticsResult(
            executed = false,
            detail = "skipped",
        ),
        keyMetadataShape: KeyMetadataShapeResult = KeyMetadataShapeResult(
            executed = false,
            detail = "skipped",
        ),
        pureCertificateSecurityLevel: PureCertificateSecurityLevelResult = PureCertificateSecurityLevelResult(
            executed = false,
            detail = "skipped",
        ),
        operationErrorPath: OperationErrorPathResult = OperationErrorPathResult(
            executed = false,
            detail = "skipped",
        ),
        biometricIntegration: BiometricTeeIntegrationResult = BiometricTeeIntegrationResult(
            executed = false,
            detail = "skipped",
        ),
        binderHookBootstrap: BinderHookBootstrapResult = BinderHookBootstrapResult(
            executed = false,
            detail = "skipped",
        ),
        binderPatchMode: BinderPatchModeResult = BinderPatchModeResult(
            executed = false,
            detail = "skipped",
        ),
        binderChainConsistency: BinderChainConsistencyResult = BinderChainConsistencyResult(
            executed = false,
            detail = "skipped",
        ),
        updateSubcomponentStaleResponsePersistence: UpdateSubcomponentStaleResponsePersistenceResult =
            UpdateSubcomponentStaleResponsePersistenceResult(
                detail = "skipped",
            ),
    ): TeeScanArtifacts {
        return TeeScanArtifacts(
            snapshot = AttestationSnapshot(
                tier = tier,
                attestationVersion = 4,
                keymasterVersion = 4,
                attestationTier = tier,
                keymasterTier = tier,
                challengeVerified = true,
                challengeSummary = "len=32",
                rootOfTrust = RootOfTrustSnapshot(
                    verifiedBootKeyHex = "abcd",
                    deviceLocked = true,
                    verifiedBootState = "Verified",
                    verifiedBootHashHex = "12345678",
                ),
                osVersion = "14.0.0",
                osPatchLevel = "2026-03",
                vendorPatchLevel = "2026-03-05",
                bootPatchLevel = "2026-03-05",
                keyProperties = AttestedKeyProperties(
                    algorithm = "EC",
                    keySize = 256,
                    ecCurve = "P-256",
                    origin = "Generated",
                    rollbackResistant = true,
                ),
                authState = AttestedAuthState(noAuthRequired = true),
                applicationInfo = AttestedApplicationInfo(packageNames = listOf("com.eltavine.duckdetector")),
                deviceInfo = deviceInfo,
                deviceUniqueAttestation = false,
                trustedAttestationIndex = 1,
                rawCertificates = emptyList(),
                displayCertificates = emptyList(),
            ),
            trust = trust,
            chainStructure = chainStructure,
            rkp = rkp,
            crl = CrlStatusResult(
                networkState = networkState,
                revokedCertificates = crlRevokedCertificates,
            ),
            pairConsistency = KeyPairConsistencyResult(
                keyMatchesCertificate = true,
                medianSignMicros = 1800,
                detail = "ok",
            ),
            aesGcm = aesGcm,
            lifecycle = KeyLifecycleResult(
                created = true,
                deleteRemovedAlias = true,
                regeneratedFreshMaterial = true,
                detail = "ok",
            ),
            timing = timing,
            timingSideChannel = timingSideChannel,
            oversizedChallenge = oversizedChallenge,
            keyboxImport = KeyboxImportResult(
                executed = false,
                markerPreserved = true,
                marker = KeyboxImportProbe.FIXTURE_MARKER,
                detail = "skipped",
            ),
            importKeyRetainedAttestationNarrative = importKeyRetainedAttestationNarrative,
            keystore2Hook = keystore2Hook,
            generateModeParcelFingerprint = generateModeParcelFingerprint,
            grantDomainFullChainSplit = grantDomainFullChainSplit,
            syntheticGrantGranteeBlindReadback = syntheticGrantGranteeBlindReadback,
            syntheticGrantGetKeyEntryAccessVectorBlindness = syntheticGrantGetKeyEntryAccessVectorBlindness,
            grantSelfDomainFullChainSplit = grantSelfDomainFullChainSplit,
            legacyKeystorePath = legacyKeystorePath,
            listEntriesConsistency = listEntriesConsistency,
            listEntriesBatched = listEntriesBatched,
            keyMetadataSemantics = keyMetadataSemantics,
            keyMetadataShape = keyMetadataShape,
            pureCertificate = PureCertificateResult(
                pureCertificateReturnsNullKey = true,
                detail = "ok",
            ),
            pureCertificateSecurityLevel = pureCertificateSecurityLevel,
            operationErrorPath = operationErrorPath,
            biometricIntegration = biometricIntegration,
            binderHookBootstrap = binderHookBootstrap,
            binderPatchMode = binderPatchMode,
            binderChainConsistency = binderChainConsistency,
            updateSubcomponent = UpdateSubcomponentResult(
                updateSucceeded = true,
                keyNotFoundStyleFailure = false,
                detail = "ok",
            ),
            updateSubcomponentStaleResponsePersistence = updateSubcomponentStaleResponsePersistence,
            pruning = OperationPruningResult(
                suspicious = false,
                operationsCreated = 18,
                invalidatedOperations = 2,
                detail = "ok",
            ),
            dualAlgorithm = dualAlgorithm,
            idAttestation = idAttestation,
            strongBox = strongBox,
            native = native,
            soter = soter,
            bootConsistency = bootConsistency,
        )
    }
}
