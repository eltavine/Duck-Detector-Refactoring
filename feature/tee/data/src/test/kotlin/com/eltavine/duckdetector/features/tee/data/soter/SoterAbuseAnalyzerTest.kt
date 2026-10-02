package com.eltavine.duckdetector.features.tee.data.soter

import com.eltavine.duckdetector.features.tee.domain.TeeSoterAnomalyKind
import java.util.Base64
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SoterAbuseAnalyzerTest {

    private val analyzer = SoterAbuseAnalyzer()

    @Test
    fun `d-soter fixed key zero signature cpu id and counter warn`() {
        val anomalies = analyzer.analyze(
            listOf(dSoterKey()),
            service(),
        ).map { it.kind }

        assertTrue(TeeSoterAnomalyKind.D_SOTER_FIXED_SPKI in anomalies)
        assertTrue(TeeSoterAnomalyKind.D_SOTER_ZERO_SIGNATURE in anomalies)
        assertTrue(TeeSoterAnomalyKind.D_SOTER_ZERO_CPU_ID in anomalies)
        assertTrue(TeeSoterAnomalyKind.INVALID_COUNTER in anomalies)
    }

    @Test
    fun `relay cpu id and sampled uid zero spki warn`() {
        val anomalies = analyzer.analyze(
            listOf(relayKey()),
            service(expectedUid = 10_000, uidSetupReliable = true),
        ).map { it.kind }

        assertTrue(TeeSoterAnomalyKind.KNOWN_RELAY_CPU_ID in anomalies)
        assertTrue(TeeSoterAnomalyKind.KNOWN_RELAY_SPKI in anomalies)
        assertTrue(TeeSoterAnomalyKind.UID_MISMATCH in anomalies)
    }

    @Test
    fun `uid mismatch requires reliable setup`() {
        val kinds = analyzer.analyze(
            listOf(relayKey()),
            service(expectedUid = 10_000, uidSetupReliable = false),
        ).map { it.kind }

        assertFalse(TeeSoterAnomalyKind.UID_MISMATCH in kinds)
        assertTrue(TeeSoterAnomalyKind.KNOWN_RELAY_CPU_ID in kinds)
    }

    @Test
    fun `clean unknown key does not warn`() {
        val anomalies = analyzer.analyze(
            listOf(
                key(
                    uid = "10000",
                    cpuId = "1234000000000000",
                    counter = 1,
                    signature = Base64.getEncoder().encodeToString(ByteArray(256) { (it + 1).toByte() }),
                    publicKey = UNKNOWN_PUBLIC_KEY,
                )
            ),
            service(expectedUid = 10_000, uidSetupReliable = true),
        )

        assertTrue(anomalies.none { it.kind == TeeSoterAnomalyKind.D_SOTER_FIXED_SPKI })
    }

    @Test
    fun `missing fields do not warn`() {
        val anomalies = analyzer.analyze(
            listOf(
                key(
                    uid = null,
                    cpuId = "",
                    counter = null,
                    signature = "",
                    publicKey = "not a pem",
                )
            ),
            service(),
        )

        assertTrue(anomalies.none { it.kind == TeeSoterAnomalyKind.D_SOTER_ZERO_SIGNATURE })
    }

    @Test
    fun `ask and auth cpu ids must agree when reliable`() {
        val anomalies = analyzer.analyze(
            listOf(
                key(uid = "10000", cpuId = "1234000000000000", counter = 1, signature = "AAA"),
                key(uid = "10000", cpuId = "5678000000000000", counter = 2, signature = "AAA"),
            ),
            service(expectedUid = 10_000, uidSetupReliable = true),
        ).map { it.kind }

        assertTrue(TeeSoterAnomalyKind.CPU_ID_MISMATCH in anomalies)
    }

    @Test
    fun `nonzero or malformed signatures are not zero signatures`() {
        val anomalies = analyzer.analyze(
            listOf(
                key(
                    uid = "10000",
                    cpuId = "1234000000000000",
                    counter = 1,
                    signature = Base64.getEncoder().encodeToString(ByteArray(256) { (it + 1).toByte() }),
                    publicKey = UNKNOWN_PUBLIC_KEY,
                )
            ),
            service(),
        )

        assertTrue(anomalies.isEmpty())
    }

    @Test
    fun `stopped vendor service with successful transaction warns`() {
        val anomalies = analyzer.analyze(
            emptyList(),
            service(vendorStopped = true),
        ).map { it.kind }

        assertTrue(TeeSoterAnomalyKind.SOFTWARE_HAL_TAKEOVER in anomalies)
    }

    private fun service(
        expectedUid: Int? = null,
        uidSetupReliable: Boolean = false,
        vendorStopped: Boolean = false,
    ) = SoterServiceEvidence(expectedUid, uidSetupReliable, vendorStopped)

    private fun key(
        uid: String?,
        cpuId: String,
        counter: Long?,
        signature: String?,
        signatureBytes: ByteArray? = null,
        publicKey: String = D_SOTER_PUBLIC_KEY,
    ): SoterKeyEvidence {
        val json = buildString {
            append('{')
            append("\"pub_key\":\"").append(publicKey.replace("\n", "\\n")).append('"')
            append(",\"cpu_id\":\"").append(cpuId).append('"')
            if (counter != null) append(",\"counter\":").append(counter) else append(",\"counter\":-1")
            append(",\"uid\":\"").append(uid ?: -1).append('"')
            append('}')
        }
        return SoterKeyEvidence(
            role = SoterKeyRole.ASK,
            alias = null,
            preExisted = true,
            rawJson = json,
            signatureBase64 = signature ?: signatureBytes?.let {
                Base64.getEncoder().encodeToString(it)
            },
            publicPem = publicKey,
        )
    }

    private fun dSoterKey() = key(
        uid = "0",
        cpuId = "0000000000000000",
        counter = 0,
        signature = Base64.getEncoder().encodeToString(ByteArray(256)),
    )

    private fun relayKey() = key(
        uid = "0",
        cpuId = "090000005171734c42866bea148b21f5",
        counter = 1,
        signature = Base64.getEncoder().encodeToString(ByteArray(256) { (it + 1).toByte() }),
        publicKey = RELAY_UID_ZERO_PUBLIC_KEY,
    )

    private companion object {
        private const val D_SOTER_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw8gEMK6J6jBvJr1b9K8j
o4jMHF5D4BoHYXTsRov+v+clqEwXntTeXrOcQeuQX9Fys5S3Jmbs6safW1vmbJps
k8Qe7wbi9p1v9uh3JzmF3j2Mw+tXtGI9h/1Vm1n6T3GrQJQ+tvuQ+vN8n6kMYl64
J7CuyYw6P5vl6Z4WlfhdY5oJc0Q9T6xVwK6bg3DOjFEq5k1DTXJZuzqjONyYCuuP
v7TTuLT8yT0+9m+CF7i65DKQJE3Ak0dCj0Ar1sIH7yLPlvWv85ExKYOvCXLdB6t8
eWg0/eeoPHDLLv11Oyq9JR0gDk0iHT5SWG2FHKY5xIb3C2we8O7CVOaPwIDAQAB
-----END PUBLIC KEY-----"""

        private const val RELAY_UID_ZERO_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAptIvEAJS9CJ+MzqKIWTV
0QI+AAXgR3g8C+9Iq9Q+EoqZ3QZD23XQRIdJlvSfE+/DkWpDSzuJC8NfUbkzoPTQ
nqANVgLZl9u3mcVSoqSOwszI7EhPQto567b0/GF11BTNYpaXRQqSBdOqcJMKzHeZ
mR3HCLQaMnH3pJB7tusftrH1GA897VD+kVk6RYIknwKmv+Ui5DqnKc9OtCkfrG8x
D35nQu8HYigil+5CIjRgIhXb6AlljX+CU/JZjhta4MsX10X4kitwVboR+4C/luq3
l7ICMLKXKpnU3nn3ZNfFwqPB6ptD5b5RfjUP4cbrkceSoPhbwK/a0Zt0uX7o91Ra
hQIDAQAB
-----END PUBLIC KEY-----"""

        private const val UNKNOWN_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1V+zX8ENmve8vC6mFDwD
vwrCjBkZ4AHBh1CB9hLFTX3GD0sCLFTwP5Mc1RLmUoMkoUp3SI2DD08rzX7fOAxL
OWlznG2BbcTggePL5s9tYgT8eTBgsGMC+5jLD6AkqIPGsLPcFTHBgrjbpIhLZWsf
5wiD1PrM/xUeixDbwm2ckev+Hfv9WAd+wR7TOBrUucKiia1q5DmJAPBLp+DfRY2R
rrppSghPEQIpaGZKST7m7NcWDLfhu/rIfBwsO4wrtUymI8d/PTARzLYAqihCbwS7
1epFkm1NbgIrfE+TJ0Lh7PFh1Qk2QhyS2SDsf5E2wII=/
-----END PUBLIC KEY-----"""
    }
}
