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

package com.eltavine.duckdetector.features.tee.data.attestation

import java.math.BigInteger
import java.security.Principal
import java.security.PublicKey
import java.security.cert.CertificateEncodingException
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AttestationExtensionParserTest {

    private val parser = AttestationExtensionParser()

    @Test
    fun `local self signed placeholder is not exposed as attestation chain`() {
        val snapshot = parser.parse(
            chain = listOf(
                FakeX509Certificate(
                    subject = "CN=DuckDetector Tee, O=Eltavine",
                    issuer = "CN=DuckDetector Tee, O=Eltavine",
                    extensionValue = null,
                ),
            ),
            expectedChallenge = byteArrayOf(1, 2, 3),
        )

        assertEquals("Attestation extension not found", snapshot.errorMessage)
        assertTrue(snapshot.displayCertificates.isEmpty())
        assertEquals(1, snapshot.rawCertificates.size)
    }

    @Test
    fun `chain stays visible when attestation extension is present even if parsing fails`() {
        val snapshot = parser.parse(
            chain = listOf(
                FakeX509Certificate(
                    subject = "CN=Leaf, O=Issuer",
                    issuer = "CN=Issuer, O=Root",
                    extensionValue = byteArrayOf(0x01, 0x02, 0x03),
                ),
            ),
            expectedChallenge = byteArrayOf(4, 5, 6),
        )

        assertEquals(1, snapshot.displayCertificates.size)
        assertTrue(!snapshot.errorMessage.isNullOrBlank())
    }

    @Test
    fun `display labels distinguish generated key certificate from attestation certificate`() {
        val snapshot = parser.parse(
            chain = listOf(
                FakeX509Certificate(
                    subject = "CN=DuckDetector Tee, O=Eltavine",
                    issuer = "CN=Issuer A, O=Root",
                    extensionValue = null,
                ),
                FakeX509Certificate(
                    subject = "CN=Attestation Carrier, O=Issuer",
                    issuer = "CN=Root Carrier, O=Root",
                    extensionValue = byteArrayOf(0x01, 0x02, 0x03),
                ),
                FakeX509Certificate(
                    subject = "CN=Root Carrier, O=Root",
                    issuer = "CN=Root Carrier, O=Root",
                    extensionValue = null,
                ),
            ),
            expectedChallenge = byteArrayOf(7, 8, 9),
        )

        assertEquals(
            listOf(
                "Generated key certificate",
                "Attestation certificate",
                "Root certificate",
            ),
            snapshot.displayCertificates.map { it.slotLabel },
        )
    }

    private class FakeX509Certificate(
        private val subject: String,
        private val issuer: String,
        private val extensionValue: ByteArray?,
    ) : X509Certificate() {

        private val subjectPrincipal = X500Principal(subject)
        private val issuerPrincipal = X500Principal(issuer)
        private val publicKey = FakePublicKey()
        private val notBefore = Date(0L)
        private val notAfter = Date(86_400_000L)

        override fun checkValidity() = Unit

        override fun checkValidity(date: Date?) = Unit

        override fun getVersion(): Int = 3

        override fun getSerialNumber(): BigInteger = BigInteger.ONE

        override fun getIssuerDN(): Principal = issuerPrincipal

        override fun getSubjectDN(): Principal = subjectPrincipal

        override fun getNotBefore(): Date = notBefore

        override fun getNotAfter(): Date = notAfter

        override fun getTBSCertificate(): ByteArray = ByteArray(0)

        override fun getSignature(): ByteArray = ByteArray(0)

        override fun getSigAlgName(): String = "SHA256withECDSA"

        override fun getSigAlgOID(): String = "1.2.840.10045.4.3.2"

        override fun getSigAlgParams(): ByteArray? = null

        override fun getIssuerUniqueID(): BooleanArray? = null

        override fun getSubjectUniqueID(): BooleanArray? = null

        override fun getKeyUsage(): BooleanArray? = null

        override fun getBasicConstraints(): Int = -1

        @Throws(CertificateEncodingException::class)
        override fun getEncoded(): ByteArray = ByteArray(0)

        override fun verify(key: PublicKey?) = Unit

        override fun verify(key: PublicKey?, sigProvider: String?) = Unit

        override fun toString(): String = "FakeX509Certificate(subject=$subject, issuer=$issuer)"

        override fun getPublicKey(): PublicKey = publicKey

        override fun getCriticalExtensionOIDs(): MutableSet<String>? = null

        override fun getExtensionValue(oid: String?): ByteArray? {
            return if (oid == "1.3.6.1.4.1.11129.2.1.17") extensionValue else null
        }

        override fun getNonCriticalExtensionOIDs(): MutableSet<String>? = null

        override fun hasUnsupportedCriticalExtension(): Boolean = false

        override fun getSubjectX500Principal(): X500Principal = subjectPrincipal

        override fun getIssuerX500Principal(): X500Principal = issuerPrincipal
    }

    private class FakePublicKey : PublicKey {
        override fun getAlgorithm(): String = "EC"

        override fun getFormat(): String = "X.509"

        override fun getEncoded(): ByteArray = ByteArray(0)
    }
}
