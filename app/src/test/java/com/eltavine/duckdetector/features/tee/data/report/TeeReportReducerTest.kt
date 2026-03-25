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
import com.eltavine.duckdetector.features.tee.data.verification.boot.BootConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.IdAttestationResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationPruningResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentResult
import com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorResult
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkMode
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkState
import com.eltavine.duckdetector.features.tee.domain.TeeRkpState
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeSoterState
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import com.eltavine.duckdetector.features.tee.domain.TeeTrustRoot
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
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
    fun `disabled crl state uses settings wording`() {
        val report = reducer.reduce(
            baseArtifacts(
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.SKIPPED,
                    summary = "Online CRL disabled in Settings.",
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Trust" }.items.any {
            it.title == "CRL" && it.body.contains("Disabled in Settings")
        })
        assertTrue(report.signals.any { it.label == "CRL" && it.value == "Disabled" })
    }

    @Test
    fun `refresh failed crl state is surfaced as degraded`() {
        val report = reducer.reduce(
            baseArtifacts(
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.ERROR,
                    summary = "CRL refresh timed out.",
                    detail = "CRL refresh timed out.",
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Trust" }.items.any {
            it.title == "CRL" &&
                    it.body.contains("Refresh failed") &&
                    it.body.contains("timed out")
        })
        assertTrue(report.signals.any { it.label == "CRL" && it.value == "Error" && it.level == TeeSignalLevel.WARN })
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
        trust: CertificateTrustResult = CertificateTrustResult(
            trustRoot = TeeTrustRoot.GOOGLE,
            chainLength = 3,
            chainSignatureValid = true,
            googleRootMatched = true,
        ),
        rkp: TeeRkpState = TeeRkpState(),
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
            timing = TimingAnomalyResult(
                suspicious = false,
                medianMicros = 1800,
                detail = "ok",
            ),
            oversizedChallenge = oversizedChallenge,
            keyboxImport = KeyboxImportResult(
                executed = false,
                markerPreserved = true,
                marker = KeyboxImportProbe.FIXTURE_MARKER,
                detail = "skipped",
            ),
            keystore2Hook = keystore2Hook,
            pureCertificate = PureCertificateResult(
                pureCertificateReturnsNullKey = true,
                detail = "ok",
            ),
            updateSubcomponent = UpdateSubcomponentResult(
                updateSucceeded = true,
                keyNotFoundStyleFailure = false,
                detail = "ok",
            ),
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
            soter = TeeSoterState(),
            bootConsistency = bootConsistency,
        )
    }
}
