package com.eltavine.duckdetector.features.bootloader.data.repository

import com.eltavine.duckdetector.capability.attestation.data.BootConsistencyResult
import com.eltavine.duckdetector.features.bootloader.data.widevine.WidevineBootloaderEvidence
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingSeverity
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodOutcome
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BootloaderConsistencyFindingsTest {
    @Test
    fun `readable runtime properties without comparison do not establish alignment`() {
        val result = BootConsistencyResult(
            runtimePropsAvailable = true,
            runtimeVbmetaDigest = "aabb",
            detail = "Attested root of trust was missing.",
        )

        val finding = findings(result).single()

        assertEquals("Not compared", finding.value)
        assertEquals(BootloaderFindingSeverity.INFO, finding.severity)
        assertEquals(result.detail, finding.detail)
    }

    @Test
    fun `unavailable runtime properties do not establish alignment`() {
        val finding = findings(BootConsistencyResult()).single()

        assertEquals("Not compared", finding.value)
        assertEquals(BootloaderFindingSeverity.INFO, finding.severity)
    }

    @Test
    fun `completed comparison without anomaly reports alignment`() {
        val finding = findings(
            BootConsistencyResult(
                runtimePropsAvailable = true,
                runtimeComparisonPerformed = true,
                runtimeVbmetaDigest = "aabb",
            ),
        ).single()

        assertEquals("Aligned", finding.value)
        assertEquals(BootloaderFindingSeverity.SAFE, finding.severity)
    }

    @Test
    fun `each hard anomaly takes precedence over completed comparison`() {
        val cases = listOf(
            "vbmeta_digest_mismatch" to BootConsistencyResult(vbmetaDigestMismatch = true),
            "vbmeta_digest_missing" to BootConsistencyResult(vbmetaDigestMissingWhileAttestedHashPresent = true),
            "boot_hash_all_zero" to BootConsistencyResult(verifiedBootHashAllZeros = true),
            "boot_key_all_zero" to BootConsistencyResult(verifiedBootKeyAllZeros = true),
        )
        for ((id, result) in cases) {
            for (performed in listOf(false, true)) {
                val findings = findings(result.copy(
                    runtimePropsAvailable = true,
                    runtimeComparisonPerformed = performed,
                ))

                assertEquals(id, findings.single().id)
                assertEquals(BootloaderFindingSeverity.DANGER, findings.single().severity)
                assertFalse(findings.any { it.id == "boot_consistency_clean" })
            }
        }
    }

    @Test
    fun `simultaneous anomalies retain all findings`() {
        val findings = findings(BootConsistencyResult(
            vbmetaDigestMismatch = true,
            verifiedBootHashAllZeros = true,
            verifiedBootKeyAllZeros = true,
            runtimePropsAvailable = true,
            runtimeComparisonPerformed = true,
        ))

        assertEquals(3, findings.size)
        assertTrue(findings.all { it.severity == BootloaderFindingSeverity.DANGER })
    }

    private fun findings(result: BootConsistencyResult) = buildConsistencyFindings(
        bootConsistency = result,
        sourceSignals = emptyList(),
        consistencySignals = emptyList(),
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
    )
}
