package com.eltavine.duckdetector.features.tee.data.verification.rkp

import com.eltavine.duckdetector.features.tee.data.verification.certificate.ChainStructureResult
import com.eltavine.duckdetector.features.tee.data.verification.certificate.ChainStructureAnalyzer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.cert.X509Certificate
import java.math.BigInteger
import java.security.PublicKey
import java.util.Date
import javax.security.auth.x500.X500Principal

class RkpExtensionAnalyzerTest {
    private val analyzer = RkpExtensionAnalyzer()
    private val structure = ChainStructureResult(
        chainLength = 3,
        attestationExtensionCount = 1,
        trustedAttestationIndex = 0,
        provisioningIndex = 1,
        detail = "fixture",
    )

    @Test
    fun `verified provisioning metadata is decoded and explicitly marked server signed`() {
        val result = analyzer.analyze(chain(), structure, googleRootMatched = true, chainSignatureValid = true)
        assertTrue(result.provisioned)
        assertTrue(result.serverSigned)
        assertEquals("Acme", result.provisioningManufacturer)
        assertEquals("TEE", result.validatedEntity)
        assertTrue(result.buildMetadata!!.contains("NOT_APPROVED"))
        assertNull(result.provisioningInfoIssue)
    }

    @Test
    fun `root matching alone cannot authenticate substituted intermediate metadata`() {
        val result = analyzer.analyze(chain(), structure, googleRootMatched = true, chainSignatureValid = false)
        assertTrue(result.provisioned)
        assertFalse(result.serverSigned)
        assertNull(result.provisioningManufacturer)
        assertNull(result.buildMetadata)
        assertNotNull(result.consistencyIssue)
    }

    @Test
    fun `untrusted root misplaced extension and missing attestation withhold metadata`() {
        val untrusted = analyzer.analyze(chain(), structure, googleRootMatched = false, chainSignatureValid = true)
        val misplaced = analyzer.analyze(chain(), structure.copy(trustedAttestationIndex = 1), true, true)
        val noAttestation = analyzer.analyze(chain(), structure.copy(trustedAttestationIndex = null), true, true)
        for (result in listOf(untrusted, misplaced, noAttestation)) {
            assertFalse(result.serverSigned)
            assertNull(result.buildMetadata)
            assertNotNull(result.consistencyIssue)
        }
    }

    @Test
    fun `malformed metadata leaves provisioning observed with an explicit decoding issue`() {
        val result = analyzer.analyze(chain(derCbor("a1 05")), structure, true, true)
        assertTrue(result.provisioned)
        assertTrue(result.serverSigned)
        assertNull(result.buildMetadata)
        assertNotNull(result.provisioningInfoIssue)
    }

    @Test
    fun `no provisioning extension is a distinct absence`() {
        val result = analyzer.analyze(emptyList(), ChainStructureResult(detail = "empty"), true, true)
        assertFalse(result.provisioned)
        assertNull(result.buildMetadata)
        assertNull(result.provisioningInfoIssue)
        assertNull(result.consistencyIssue)
    }

    @Test
    fun `leaf added extensions cannot override the provisioning certificate nearest the root`() {
        val forged = derCbor("a3 01 00 04 63 544545 05 a1 01 68 415050524f564544")
        val server = derCbor("a3 01 00 04 63 544545 05 a1 01 6c 4e4f545f415050524f564544")
        val chain = listOf(
            ProvisioningCertificate(forged, attestation = true),
            ProvisioningCertificate(attestation = true),
            ProvisioningCertificate(server),
            ProvisioningCertificate(),
        )
        val structure = ChainStructureAnalyzer().inspect(chain)
        assertEquals(1, structure.trustedAttestationIndex)
        assertEquals(2, structure.provisioningIndex)
        val result = analyzer.analyze(chain, structure, true, true)
        assertEquals(2, result.attestationExtensionCount)
        assertTrue(result.serverSigned)
        val metadata = requireNotNull(result.buildMetadata)
        assertTrue(metadata.contains("\"NOT_APPROVED\""))
        assertFalse(metadata.contains("\"APPROVED\""))
    }

    private fun chain(
        extension: ByteArray = derCbor("a4 01 00 03 64 41636d65 04 63 544545 05 a1 01 6c 4e4f545f415050524f564544"),
    ): List<X509Certificate> {
        return listOf(ProvisioningCertificate(), ProvisioningCertificate(extension), ProvisioningCertificate())
    }
}

@Suppress("DEPRECATION")
private class ProvisioningCertificate(
    private val extension: ByteArray? = null,
    private val attestation: Boolean = false,
) : X509Certificate() {
    override fun getExtensionValue(oid: String?): ByteArray? = when (oid) {
        "1.3.6.1.4.1.11129.2.1.30" -> extension
        "1.3.6.1.4.1.11129.2.1.17" -> if (attestation) byteArrayOf(0x30, 0x00) else null
        else -> null
    }

    override fun getEncoded() = byteArrayOf()
    override fun verify(key: PublicKey?) = Unit
    override fun verify(key: PublicKey?, provider: String?) = Unit
    override fun toString() = "ProvisioningCertificate"
    override fun getPublicKey(): PublicKey = error("Not used by extension analysis")
    override fun checkValidity() = Unit
    override fun checkValidity(date: Date?) = Unit
    override fun getVersion() = 3
    override fun getSerialNumber() = BigInteger.ONE
    override fun getIssuerDN() = X500Principal("CN=fixture")
    override fun getSubjectDN() = X500Principal("CN=fixture")
    override fun getIssuerX500Principal() = X500Principal("CN=fixture")
    override fun getSubjectX500Principal() = X500Principal("CN=fixture")
    override fun getNotBefore() = Date(0)
    override fun getNotAfter() = Date(86_400_000)
    override fun getTBSCertificate() = byteArrayOf()
    override fun getSignature() = byteArrayOf()
    override fun getSigAlgName() = "NONE"
    override fun getSigAlgOID() = "1.2.3"
    override fun getSigAlgParams(): ByteArray? = null
    override fun getIssuerUniqueID(): BooleanArray? = null
    override fun getSubjectUniqueID(): BooleanArray? = null
    override fun getKeyUsage(): BooleanArray? = null
    override fun getBasicConstraints() = -1
    override fun getCriticalExtensionOIDs(): MutableSet<String>? = null
    override fun getNonCriticalExtensionOIDs(): MutableSet<String>? = null
    override fun hasUnsupportedCriticalExtension() = false
}
