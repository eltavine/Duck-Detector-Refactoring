package com.eltavine.duckdetector.features.bootloader.data.repository

import com.eltavine.duckdetector.capability.attestation.data.AttestationSnapshot
import com.eltavine.duckdetector.capability.attestation.data.BootConsistencyProbe
import com.eltavine.duckdetector.capability.attestation.data.BootConsistencyResult
import com.eltavine.duckdetector.capability.attestation.data.CertificateTrustResult
import com.eltavine.duckdetector.capability.attestation.data.PropertyReadResult
import com.eltavine.duckdetector.capability.attestation.data.RootOfTrustSnapshot
import com.eltavine.duckdetector.capability.attestation.data.SystemPropertyReader
import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertiesNativeSnapshot
import com.eltavine.duckdetector.features.bootloader.data.widevine.WidevineBootloaderEvidence
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderEvidenceMode
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodOutcome
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodResult
import org.junit.Assert.assertEquals
import org.junit.Test

class BootloaderMethodsTest {
    private val snapshot = AttestationSnapshot(
        tier = TeeTier.TEE,
        attestationVersion = 4,
        keymasterVersion = 4,
        attestationTier = TeeTier.TEE,
        keymasterTier = TeeTier.TEE,
        challengeVerified = true,
        challengeSummary = "len=32",
        rootOfTrust = null,
        osVersion = null,
        osPatchLevel = null,
        vendorPatchLevel = null,
        bootPatchLevel = null,
        rawCertificates = emptyList(),
        displayCertificates = emptyList(),
    )

    @Test
    fun `probe skips cannot become a clean method result`() {
        val root = RootOfTrustSnapshot("1122", true, "Verified", "aabb")
        val probe = BootConsistencyProbe(SystemPropertyReader {
            PropertyReadResult(available = true, value = "aabb")
        })
        for (uncomparableRoot in listOf(
            null,
            root.copy(verifiedBootHashHex = null),
            root.copy(verifiedBootState = "Unverified"),
            root.copy(verifiedBootState = "Failed"),
            root.copy(verifiedBootState = "Unknown"),
        )) {
            val attestation = snapshot.copy(rootOfTrust = uncomparableRoot)
            val method = bootMethod(probe.inspect(attestation), attestation)

            assertEquals("Not compared", method.summary)
            assertEquals(BootloaderMethodOutcome.SUPPORT, method.outcome)
        }
    }

    @Test
    fun `fresh probe comparison reports a match or an anomaly`() {
        val attestation = snapshot.copy(rootOfTrust = RootOfTrustSnapshot("1122", true, "Verified", "aabb"))
        for (runtimeDigest in listOf("aabb", "ffee")) {
            val probe = BootConsistencyProbe(SystemPropertyReader {
                PropertyReadResult(available = true, value = runtimeDigest)
            })
            val method = bootMethod(probe.inspect(attestation), attestation)

            assertEquals(if (runtimeDigest == "aabb") "Aligned" else "Anomaly", method.summary)
            assertEquals(
                if (runtimeDigest == "aabb") BootloaderMethodOutcome.CLEAN else BootloaderMethodOutcome.DANGER,
                method.outcome,
            )
        }
    }

    @Test
    fun `boot method is support when runtime digest was not compared`() {
        for (available in listOf(false, true)) {
            val result = BootConsistencyResult(
                runtimePropsAvailable = available,
                detail = "Comparison was unavailable.",
            )

            val method = bootMethod(result)

            assertEquals("Not compared", method.summary)
            assertEquals(BootloaderMethodOutcome.SUPPORT, method.outcome)
            assertEquals(result.detail, method.detail)
        }
    }

    @Test
    fun `boot method is clean only after a completed comparison`() {
        val method = bootMethod(BootConsistencyResult(
            runtimePropsAvailable = true,
            runtimeComparisonPerformed = true,
        ))

        assertEquals("Aligned", method.summary)
        assertEquals(BootloaderMethodOutcome.CLEAN, method.outcome)
    }

    @Test
    fun `boot method preserves each anomaly regardless of comparison availability`() {
        for (result in listOf(
            BootConsistencyResult(vbmetaDigestMismatch = true),
            BootConsistencyResult(vbmetaDigestMissingWhileAttestedHashPresent = true),
            BootConsistencyResult(verifiedBootHashAllZeros = true),
            BootConsistencyResult(verifiedBootKeyAllZeros = true),
        )) {
            for (performed in listOf(false, true)) {
                val method = bootMethod(result.copy(
                    runtimePropsAvailable = true,
                    runtimeComparisonPerformed = performed,
                ))

                assertEquals("Anomaly", method.summary)
                assertEquals(BootloaderMethodOutcome.DANGER, method.outcome)
            }
        }
    }

    private fun bootMethod(
        result: BootConsistencyResult,
        attestation: AttestationSnapshot = snapshot,
    ) = buildMethods(
        evidenceMode = BootloaderEvidenceMode.UNAVAILABLE,
        attestation = attestation,
        trust = CertificateTrustResult(),
        bootConsistency = result,
        nativeSnapshot = SystemPropertiesNativeSnapshot(),
        observedPropertyCount = 0,
        reflectionHitCount = 0,
        getpropHitCount = 0,
        sourceSignals = emptyList(),
        consistencySignals = emptyList(),
        propertyContext = BootloaderPropertyContext.empty(),
        widevineEvidence = WidevineBootloaderEvidence(
            findings = emptyList(),
            impacts = emptyList(),
            method = BootloaderMethodResult(
                label = "Widevine credential",
                summary = "Unavailable",
                outcome = BootloaderMethodOutcome.SUPPORT,
            ),
            anomalyCount = 0,
        ),
    ).single { it.label == "Boot consistency" }
}
