/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.features.tee.data.soter

import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeSoterAnomaly
import com.eltavine.duckdetector.features.tee.domain.TeeSoterAnomalyKind
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SoterAbuseAnalyzerTest {

    private val analyzer = SoterAbuseAnalyzer()

    @Test
    fun `d-soter placeholder reply fails on its key and signature`() {
        val anomalies = analyze(
            SoterKeyEvidence(SoterKeyRole.ASK, D_SOTER_EXPORT_JSON, base64(ByteArray(256))),
            SoterKeyEvidence(SoterKeyRole.AUTH_KEY, D_SOTER_EXPORT_JSON, base64(ByteArray(256))),
        )

        assertEquals(
            listOf(
                TeeSoterAnomalyKind.D_SOTER_FIXED_SPKI,
                TeeSoterAnomalyKind.D_SOTER_ZERO_SIGNATURE,
                TeeSoterAnomalyKind.D_SOTER_ZERO_CPU_ID,
                TeeSoterAnomalyKind.UID_MISMATCH,
                TeeSoterAnomalyKind.INVALID_COUNTER,
            ),
            anomalies.map { it.kind },
        )
        assertEquals(TeeSignalLevel.FAIL, anomalies.levelOf(TeeSoterAnomalyKind.D_SOTER_FIXED_SPKI))
        assertEquals(TeeSignalLevel.FAIL, anomalies.levelOf(TeeSoterAnomalyKind.D_SOTER_ZERO_SIGNATURE))
        assertEquals(TeeSignalLevel.WARN, anomalies.levelOf(TeeSoterAnomalyKind.D_SOTER_ZERO_CPU_ID))
        assertTrue(anomalies.first().detail.contains("ASK and AuthKey"))
    }

    @Test
    fun `placeholder key still matches when wrapped in pem armour`() {
        val armoured = D_SOTER_PLACEHOLDER_KEY.chunked(64)
            .joinToString(separator = "\n", prefix = "-----BEGIN PUBLIC KEY-----\n", postfix = "\n-----END PUBLIC KEY-----\n")
        val anomalies = analyze(
            blob(signature = NON_ZERO_SIGNATURE) {
                put("pub_key", armoured)
                put("cpu_id", "00000000201ca0e1874c2b3eac6b67c2")
                put("counter", 3)
                put("uid", REQUESTED_UID.toString())
            },
        )

        assertEquals(listOf(TeeSoterAnomalyKind.D_SOTER_FIXED_SPKI), anomalies.map { it.kind })
    }

    @Test
    fun `authkey exported by a working device raises nothing`() {
        val anomalies = analyzer.analyze(
            listOf(SoterKeyEvidence(SoterKeyRole.AUTH_KEY, TENCENT_SAMPLE_AUTH_KEY_JSON, TENCENT_SAMPLE_AUTH_KEY_SIGNATURE)),
            SoterServiceEvidence(requestedUid = 10115, vendorHalStoppedWhileServing = false),
        )

        assertTrue(anomalies.isEmpty())
    }

    @Test
    fun `blob uid other than the requested uid warns`() {
        val anomalies = analyze(
            SoterKeyEvidence(SoterKeyRole.AUTH_KEY, TENCENT_SAMPLE_AUTH_KEY_JSON, TENCENT_SAMPLE_AUTH_KEY_SIGNATURE),
        )

        assertEquals(listOf(TeeSoterAnomalyKind.UID_MISMATCH), anomalies.map { it.kind })
        assertEquals(TeeSignalLevel.WARN, anomalies.single().level)
        assertTrue(anomalies.single().detail.contains("10115"))
    }

    @Test
    fun `default relay device cpu id warns in either case`() {
        val anomalies = analyze(
            cleanBlob(SoterKeyRole.ASK, cpuId = RELAY_CPU_ID),
            cleanBlob(SoterKeyRole.AUTH_KEY, cpuId = RELAY_CPU_ID.uppercase()),
        )

        assertEquals(listOf(TeeSoterAnomalyKind.KNOWN_RELAY_CPU_ID), anomalies.map { it.kind })
        assertEquals(TeeSignalLevel.WARN, anomalies.single().level)
    }

    @Test
    fun `default relay uid 0 ask key warns`() {
        val anomalies = analyze(
            blob(signature = NON_ZERO_SIGNATURE) {
                put("pub_key", RELAY_UID_ZERO_PUBLIC_KEY)
                put("cpu_id", "00000000201ca0e1874c2b3eac6b67c2")
                put("counter", 1)
                put("uid", REQUESTED_UID.toString())
            },
        )

        assertEquals(listOf(TeeSoterAnomalyKind.KNOWN_RELAY_SPKI), anomalies.map { it.kind })
        assertEquals(TeeSignalLevel.WARN, anomalies.single().level)
    }

    @Test
    fun `non positive counter warns only on a complete blob`() {
        val counted = analyze(
            blob(signature = NON_ZERO_SIGNATURE) {
                put("cpu_id", "00000000201ca0e1874c2b3eac6b67c2")
                put("counter", 0)
                put("uid", REQUESTED_UID.toString())
            },
        )
        val incomplete = analyze(
            blob(signature = NON_ZERO_SIGNATURE) {
                put("cpu_id", "0000000000000000")
                put("counter", 0)
            },
        )

        assertEquals(listOf(TeeSoterAnomalyKind.INVALID_COUNTER), counted.map { it.kind })
        assertTrue(counted.single().detail.contains("counter 0"))
        assertTrue(incomplete.isEmpty())
    }

    @Test
    fun `zero signature of another length is reported apart from d-soter's`() {
        val anomalies = analyze(
            SoterKeyEvidence(SoterKeyRole.ASK, TENCENT_SAMPLE_AUTH_KEY_JSON, base64(ByteArray(512))),
        )

        assertEquals(
            listOf(TeeSoterAnomalyKind.ZERO_SIGNATURE, TeeSoterAnomalyKind.UID_MISMATCH),
            anomalies.map { it.kind },
        )
        assertEquals(TeeSignalLevel.FAIL, anomalies.levelOf(TeeSoterAnomalyKind.ZERO_SIGNATURE))
        assertTrue(anomalies.first().detail.startsWith("512 zero bytes"))
    }

    @Test
    fun `zero signature still counts when the json is unreadable`() {
        val anomalies = analyze(SoterKeyEvidence(SoterKeyRole.ASK, "not json", base64(ByteArray(256))))

        assertEquals(listOf(TeeSoterAnomalyKind.D_SOTER_ZERO_SIGNATURE), anomalies.map { it.kind })
    }

    @Test
    fun `all-zero cpu id of another length is reported apart from d-soter's`() {
        val anomalies = analyze(cleanBlob(SoterKeyRole.ASK, cpuId = "0".repeat(32)))

        assertEquals(listOf(TeeSoterAnomalyKind.ZERO_CPU_ID), anomalies.map { it.kind })
        assertEquals(TeeSignalLevel.WARN, anomalies.single().level)
        assertTrue(anomalies.single().detail.contains("32 characters"))
    }

    @Test
    fun `ask and authkey from different devices warn`() {
        val anomalies = analyze(
            cleanBlob(SoterKeyRole.ASK, cpuId = "00000000201ca0e1874c2b3eac6b67c2"),
            cleanBlob(SoterKeyRole.AUTH_KEY, cpuId = "0900000026030000241a1e8e9e44c3a8e05b9c0c"),
        )

        assertEquals(listOf(TeeSoterAnomalyKind.CPU_ID_MISMATCH), anomalies.map { it.kind })
    }

    @Test
    fun `certificate backed model without readable device info raises nothing`() {
        val anomalies = analyze(
            blob(signature = null) {
                put("certs", JSONArray(listOf("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")))
                put("cpu_id", "")
                put("uid", -1)
                put("counter", -1)
            },
        )

        assertTrue(anomalies.isEmpty())
    }

    @Test
    fun `unreadable replies raise nothing`() {
        val anomalies = analyze(
            SoterKeyEvidence(SoterKeyRole.ASK, "not json", base64(NON_ZERO_SIGNATURE)),
            SoterKeyEvidence(SoterKeyRole.AUTH_KEY, null, null),
            blob(signature = null) { put("pub_key", "") },
            SoterKeyEvidence(SoterKeyRole.AUTH_KEY, JSONObject().put("uid", "n/a").toString(), "!!not base64!!"),
        )

        assertTrue(anomalies.isEmpty())
    }

    @Test
    fun `stopped stock hal while soter answered warns`() {
        val anomalies = analyzer.analyze(
            emptyList(),
            SoterServiceEvidence(requestedUid = REQUESTED_UID, vendorHalStoppedWhileServing = true),
        )

        assertEquals(listOf(TeeSoterAnomalyKind.SOFTWARE_HAL_TAKEOVER), anomalies.map { it.kind })
        assertEquals(TeeSignalLevel.WARN, anomalies.single().level)
    }

    private fun analyze(vararg keys: SoterKeyEvidence): List<TeeSoterAnomaly> =
        analyzer.analyze(keys.toList(), SoterServiceEvidence(REQUESTED_UID, vendorHalStoppedWhileServing = false))

    private fun cleanBlob(role: SoterKeyRole, cpuId: String) = blob(role, NON_ZERO_SIGNATURE) {
        put("pub_key", "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----")
        put("cpu_id", cpuId)
        put("counter", 7)
        put("uid", REQUESTED_UID.toString())
    }

    private fun blob(
        role: SoterKeyRole = SoterKeyRole.ASK,
        signature: ByteArray?,
        fields: JSONObject.() -> Unit,
    ) = SoterKeyEvidence(role, JSONObject().apply(fields).toString(), signature?.let(::base64))

    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    private fun List<TeeSoterAnomaly>.levelOf(kind: TeeSoterAnomalyKind) = single { it.kind == kind }.level

    private companion object {
        const val REQUESTED_UID = 10234
        const val RELAY_CPU_ID = "090000005171734c42866bea148b21f5"
        val NON_ZERO_SIGNATURE = ByteArray(256) { (it + 1).toByte() }

        // The pub_key OhMyKeymint pif-spoof/src/soter/wire.rs replays, joined exactly as its concat! does.
        val D_SOTER_PLACEHOLDER_KEY = listOf(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw8gEMK6J6jBvJr1b9K8j",
            "o4jMHF5D4BoHYXTsRov+v+clqEwXntTeXrOcQeuQX9Fys5S3Jmbs6safW1vmbJps",
            "k8Qe7wbi9p1v9uh3JzmF3j2Mw+tXtGI9h/1Vm1n6T3GrQJQ+tvuQ+vN8n6kMYl64",
            "J7CuyYw6P5vl6Z4WlfhdY5oJc0Q9T6xVwK6bg3DOjFEq5k1DTXJZuzqjONyYCuuP",
            "v7TTuLT8yT0+9m+CF7i65DKQJE3Ak0dCj0Ar1sIH7yLPlvWv85ExKYOvCXLdB6t8",
            "eWg0/eeoPHDLLv11Oyq9JR0gDk0iHT5SWG2FHKY5xIb3C2we8O7CVOaPwIDAQAB",
        ).joinToString("")
        val D_SOTER_EXPORT_JSON =
            """{"pub_key":"$D_SOTER_PLACEHOLDER_KEY","counter":0,"cpu_id":"0000000000000000","uid":0}"""

        // The uid 0 ASK the default relay returned when it was sampled on 2026-10-02.
        const val RELAY_UID_ZERO_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAptIvEAJS9CJ+MzqKIWTV
0QI+AAXgR3g8C+9Iq9Q+EoqZ3QZD23XQRIdJlvSfE+/DkWpDSzuJC8NfUbkzoPTQ
nqANVgLZl9u3mcVSoqSOwszI7EhPQto567b0/GF11BTNYpaXRQqSBdOqcJMKzHeZ
mR3HCLQaMnH3pJB7tusftrH1GA897VD+kVk6RYIknwKmv+Ui5DqnKc9OtCkfrG8x
D35nQu8HYigil+5CIjRgIhXb6AlljX+CU/JZjhta4MsX10X4kitwVboR+4C/luq3
l7ICMLKXKpnU3nn3ZNfFwqPB6ptD5b5RfjUP4cbrkceSoPhbwK/a0Zt0uX7o91Ra
hQIDAQAB
-----END PUBLIC KEY-----"""

        // Tencent soter soter-samples/server-sample/java/example/auth_key_json.txt and
        // auth_key_signature.bin: an AuthKey exported by a MediaTek device.
        val TENCENT_SAMPLE_AUTH_KEY_JSON = buildString {
            append("""{"pub_key":"-----BEGIN PUBLIC KEY-----\n""")
            append("""MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlywg8g3TKyDsJ7thd4pb\n""")
            append("""6HQ7TJ+UzDOH48XwfWllkGrvzXu0f3iM5AEh2iTEZB05KXwYwkRUuVg8P5HPRZwl\n""")
            append("""LADoO3g3DzzdRCqNtWug26Jg4Ca2cGHoOx7YpHSTgOLxzWjbgEqpUL02KDFrwHNi\n""")
            append("""Ti0QC6+Te29bHnvzQKy23IBu4+qIFGrjpo2MwRt0zCyts\/NQONLsOSIbLokz3og2\n""")
            append("""AKgJoG1GtmclmNnbC\/jVWQ1tIUt62Ri6OipD1lZOmsdyioYy1IuecFn5wtvrvm73\n""")
            append("""Sz49I8R\/vK8CxWSCrYfP+9FkCupoMcmhDZIKdXlTsvp55gemiy7nLkhkRB5Hu5Qf\n""")
            append("""pQIDAQAB\n-----END PUBLIC KEY-----","cpu_id":"0900000026030000241a1e8e9e44c3a8e05b9c0c",""")
            append(""""counter":240,"uid":"10115"}""")
        }
        const val TENCENT_SAMPLE_AUTH_KEY_SIGNATURE =
            "MMY2tV56p240D+gwRs9j+TB5o928dGxFzRkT+k8Xpvon2dL1WhnIhkp7Z938lyahTzT7kWWYhoYEL4G1CWBNrw/O" +
                "Bp6Tq5oeA+9ibLRnZe0+4g0VDIFt7AVffPNlEiRZm2PL6XoId8c4K621rYqBmdziTKrkwWSabbe/09KglU5Ilm+4" +
                "vtt/ns3LEtJ8DLVSry/muXbNIHcrThz0ILpy0EUzP/SdPJ07MTGFZYzXfyoR0ue6RG/7s1yfB6u7GK2IP12Fradu" +
                "go3sm7+AAis2x6gbVCeE+F/4S645BwQX1CXEnPBAtjxwmh4mxpl1QHE7/xYMmZV4ONrCuQGPcs4f/Q=="
    }
}
