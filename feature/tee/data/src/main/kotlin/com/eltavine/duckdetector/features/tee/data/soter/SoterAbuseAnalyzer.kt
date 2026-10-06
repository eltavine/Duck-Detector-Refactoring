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
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.util.Base64
import org.json.JSONObject

/** An exported ASK or AuthKey as SoterPubKeyModel holds it: the blob's JSON and its Base64 signature. */
internal data class SoterKeyEvidence(
    val role: SoterKeyRole,
    val rawJson: String?,
    val signatureBase64: String?,
)

internal enum class SoterKeyRole(val label: String) {
    ASK("ASK"),
    AUTH_KEY("AuthKey"),
}

internal data class SoterServiceEvidence(
    val requestedUid: Int,
    val vendorHalStoppedWhileServing: Boolean,
)

/**
 * Looks for reply content that a device's own Soter TA does not produce.
 *
 * A TA exports `[u32 length][JSON][RSA-PSS signature]`, and the JSON carries the TA's cpu_id and
 * the uid the caller passed through ISoterService (Tencent soter-core SoterCoreBase and
 * SoterPubKeyModel). The fixed values are the ones OhMyKeymint answers with: its D-Soter mode
 * replays D-Soter's placeholder reply, and its relay mode returns blobs made on the relay device.
 */
internal class SoterAbuseAnalyzer {

    fun analyze(keys: List<SoterKeyEvidence>, service: SoterServiceEvidence): List<TeeSoterAnomaly> {
        val blobs = keys.map(::parse)
        val reliable = blobs.filter { it.fieldsReliable }
        return buildList {
            addFor(
                blobs,
                TeeSoterAnomalyKind.D_SOTER_FIXED_SPKI,
                TeeSignalLevel.FAIL,
                matches = { it.spkiSha256 == D_SOTER_FIXED_SPKI_SHA256 },
            ) { matched -> "D-Soter's fixed placeholder public key in ${matched.roles}" }
            // No RSA signature is zero: verification maps 0 to 0, which no padding scheme accepts.
            addFor(
                blobs,
                TeeSoterAnomalyKind.D_SOTER_ZERO_SIGNATURE,
                TeeSignalLevel.FAIL,
                matches = { it.zeroSignatureBytes == RSA_2048_SIGNATURE_BYTES },
            ) { matched -> "256 zero bytes as the signature in ${matched.roles}, which no RSA signing operation produces" }
            addFor(
                blobs,
                TeeSoterAnomalyKind.ZERO_SIGNATURE,
                TeeSignalLevel.FAIL,
                matches = { blob -> blob.zeroSignatureBytes.let { it != null && it != RSA_2048_SIGNATURE_BYTES } },
            ) { matched ->
                "${matched.mapNotNull { it.zeroSignatureBytes }.distinct().joinToString()} zero bytes as the signature " +
                    "in ${matched.roles}, which no RSA signing operation produces"
            }
            addFor(
                reliable,
                TeeSoterAnomalyKind.D_SOTER_ZERO_CPU_ID,
                TeeSignalLevel.WARN,
                matches = { it.cpuId == D_SOTER_ZERO_CPU_ID },
            ) { matched -> "D-Soter's all-zero cpu_id in ${matched.roles}" }
            addFor(
                reliable,
                TeeSoterAnomalyKind.ZERO_CPU_ID,
                TeeSignalLevel.WARN,
                matches = { it.cpuId != D_SOTER_ZERO_CPU_ID && it.cpuId.all { char -> char == '0' } },
            ) { matched -> "an all-zero cpu_id of ${matched.map { it.cpuId.length }.distinct().joinToString()} characters in ${matched.roles}" }
            addFor(
                reliable,
                TeeSoterAnomalyKind.KNOWN_RELAY_CPU_ID,
                TeeSignalLevel.WARN,
                matches = { it.cpuId.equals(RELAY_CPU_ID, ignoreCase = true) },
            ) { matched -> "cpu_id $RELAY_CPU_ID in ${matched.roles}, the device behind OhMyKeymint's default Soter relay" }
            addFor(
                blobs,
                TeeSoterAnomalyKind.KNOWN_RELAY_SPKI,
                TeeSignalLevel.WARN,
                matches = { it.spkiSha256 == RELAY_UID_ZERO_SPKI_SHA256 },
            ) { matched -> "the uid 0 ASK public key of OhMyKeymint's default Soter relay in ${matched.roles}" }

            val foreignUids = reliable.mapNotNull { it.uid }.filter { it != service.requestedUid.toLong() }.distinct()
            if (foreignUids.isNotEmpty()) {
                add(
                    TeeSoterAnomaly(
                        TeeSoterAnomalyKind.UID_MISMATCH,
                        TeeSignalLevel.WARN,
                        "blob uid ${foreignUids.joinToString()} instead of the requested uid ${service.requestedUid}",
                    )
                )
            }
            val cpuIds = reliable.filterNot { it.certificateBacked }.map { it.cpuId.lowercase() }.distinct()
            if (cpuIds.size > 1) {
                add(
                    TeeSoterAnomaly(
                        TeeSoterAnomalyKind.CPU_ID_MISMATCH,
                        TeeSignalLevel.WARN,
                        "ASK and AuthKey report different cpu_ids (${cpuIds.joinToString()})",
                    )
                )
            }
            addFor(
                reliable,
                TeeSoterAnomalyKind.INVALID_COUNTER,
                TeeSignalLevel.WARN,
                matches = { blob -> blob.counter?.let { it <= 0 } == true },
            ) { matched ->
                "counter ${matched.mapNotNull { it.counter }.distinct().joinToString()} in ${matched.roles}, which is not positive"
            }
            if (service.vendorHalStoppedWhileServing) {
                add(
                    TeeSoterAnomaly(
                        TeeSoterAnomalyKind.SOFTWARE_HAL_TAKEOVER,
                        TeeSignalLevel.WARN,
                        "the stock vendor.soter service was stopped before key preparation and after the signing session opened",
                    )
                )
            }
        }
    }

    private fun MutableList<TeeSoterAnomaly>.addFor(
        blobs: List<SoterBlob>,
        kind: TeeSoterAnomalyKind,
        level: TeeSignalLevel,
        matches: (SoterBlob) -> Boolean,
        detail: (matched: List<SoterBlob>) -> String,
    ) {
        val matched = blobs.filter(matches)
        if (matched.isNotEmpty()) {
            add(TeeSoterAnomaly(kind, level, detail(matched)))
        }
    }

    private val List<SoterBlob>.roles: String
        get() = map { it.role.label }.distinct().joinToString(" and ")

    private fun parse(evidence: SoterKeyEvidence): SoterBlob {
        val signature = evidence.signatureBase64
            ?.takeIf { it.isNotBlank() }
            ?.let { runCatching { Base64.getDecoder().decode(it) }.getOrNull() }
        // The signature stands on its own, so an unreadable JSON or certificate only drops the
        // rules that read them.
        val unreadable = SoterBlob(evidence.role, signature)
        val json = evidence.rawJson
            ?.takeIf { it.isNotBlank() }
            ?.let { runCatching { JSONObject(it) }.getOrNull() }
            ?: return unreadable
        val certificateBacked = json.has(JSON_CERTS)
        val spkiSha256 = if (certificateBacked) {
            val certificatePem = json.optJSONArray(JSON_CERTS)?.optString(0)?.takeIf { it.isNotBlank() }
                ?: return unreadable
            val certificate = runCatching {
                CertificateFactory.getInstance("X.509").generateCertificate(certificatePem.byteInputStream())
            }.getOrNull() ?: return unreadable
            certificate.publicKey?.encoded?.let(::sha256Hex)
        } else {
            keyBody(json.optString(JSON_PUB_KEY))?.let(::decodedSha256)
        }
        // SoterPubKeyModel rewrites a certificate-backed model and leaves cpu_id "", uid -1 and
        // counter -1 when it could not read them from the attestation extension.
        val cpuId = json.optString(JSON_CPU_ID, "")
        val uid = wholeNumber(json.opt(JSON_UID))?.takeUnless { certificateBacked && it < 0 }
        val counter = wholeNumber(json.opt(JSON_COUNTER))?.takeUnless { certificateBacked && it < 0 }
        return SoterBlob(
            role = evidence.role,
            signature = signature,
            certificateBacked = certificateBacked,
            spkiSha256 = spkiSha256,
            cpuId = cpuId,
            uid = uid,
            counter = counter,
            fieldsReliable = cpuId.isNotBlank() && if (certificateBacked) {
                uid != null && counter != null
            } else {
                json.has(JSON_UID) && json.has(JSON_COUNTER)
            },
        )
    }

    // A TA writes uid as a JSON string ("10115") while D-Soter writes a number.
    private fun wholeNumber(value: Any?): Long? = when (value) {
        is Number -> value.toLong()
        is String -> value.trim().toLongOrNull()
        else -> null
    }

    private fun keyBody(pubKey: String): String? = pubKey.lineSequence()
        .filterNot { it.trim().startsWith("-----") }
        .joinToString("")
        .filterNot(Char::isWhitespace)
        .takeIf { it.isNotEmpty() }

    private fun decodedSha256(body: String): String? = runCatching {
        Base64.getMimeDecoder().decode(body + "=".repeat((4 - body.length % 4) % 4))
    }.getOrNull()?.let(::sha256Hex)

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private class SoterBlob(
        val role: SoterKeyRole,
        val signature: ByteArray?,
        val certificateBacked: Boolean = false,
        val spkiSha256: String? = null,
        val cpuId: String = "",
        val uid: Long? = null,
        val counter: Long? = null,
        val fieldsReliable: Boolean = false,
    ) {
        val zeroSignatureBytes: Int?
            get() = signature?.takeIf { bytes -> bytes.isNotEmpty() && bytes.all { it == 0.toByte() } }?.size
    }

    private companion object {
        const val JSON_PUB_KEY = "pub_key"
        const val JSON_CPU_ID = "cpu_id"
        const val JSON_UID = "uid"
        const val JSON_COUNTER = "counter"
        const val JSON_CERTS = "certs"
        const val RSA_2048_SIGNATURE_BYTES = 256

        // D-soter commit 6148e02e returns this fixed placeholder key and all-zero signatures. Its
        // pub_key is 383 Base64 characters without PEM armour, so the fingerprint covers the bytes
        // the text decodes to once padded.
        const val D_SOTER_FIXED_SPKI_SHA256 =
            "944f34afbf46422808152263b7df39a97a69c7bd13245a4267236f50e62ee5b3"
        const val D_SOTER_ZERO_CPU_ID = "0000000000000000"

        // Sampled from the default relay identity on 2026-10-02; all observed slots shared this cpu_id.
        const val RELAY_CPU_ID = "090000005171734c42866bea148b21f5"
        const val RELAY_UID_ZERO_SPKI_SHA256 =
            "26e10bfa8dc72caf67aaf83f4fc17560b4af0e0097dd766b6c448793c69d31cc"
    }
}
