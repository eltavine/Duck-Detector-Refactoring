package com.eltavine.duckdetector.features.bootloader.data.repository

import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingSeverity
import com.eltavine.duckdetector.features.tee.data.verification.certificate.CertificateTrustResult
import com.eltavine.duckdetector.features.tee.domain.TeeTrustRoot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BootloaderSeverityRulesTest {

    @Test
    fun `zero length trust chain maps to danger`() {
        val severity = BootloaderSeverityRules.trustRootSeverity(
            CertificateTrustResult(
                trustRoot = TeeTrustRoot.UNKNOWN,
                chainLength = 0,
            ),
        )

        assertEquals(BootloaderFindingSeverity.DANGER, severity)
    }

    @Test
    fun `unknown trust root maps to danger even when signatures are otherwise clean`() {
        val severity = BootloaderSeverityRules.trustRootSeverity(
            CertificateTrustResult(
                trustRoot = TeeTrustRoot.UNKNOWN,
                chainLength = 2,
                chainSignatureValid = true,
            ),
        )

        assertEquals(BootloaderFindingSeverity.DANGER, severity)
    }

    @Test
    fun `key pair generation failure is treated as critical attestation failure`() {
        assertTrue(
            BootloaderSeverityRules.isKeyPairGenerationFailure(
                "failed to generate a key pair"
            ),
        )
        assertFalse(
            BootloaderSeverityRules.isKeyPairGenerationFailure(
                "Attestation collection failed"
            ),
        )
    }
}
