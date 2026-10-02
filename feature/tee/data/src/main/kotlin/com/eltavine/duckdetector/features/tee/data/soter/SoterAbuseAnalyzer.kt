package com.eltavine.duckdetector.features.tee.data.soter

import com.eltavine.duckdetector.features.tee.domain.TeeSoterAnomaly
import com.eltavine.duckdetector.features.tee.domain.TeeSoterAnomalyKind
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.util.Base64
import org.json.JSONObject

internal data class SoterKeyEvidence(
    val role: SoterKeyRole,
    val alias: String?,
    val preExisted: Boolean,
    val rawJson: String?,
    val signatureBase64: String?,
    val publicPem: String?,
)

internal enum class SoterKeyRole {
    ASK,
    AUTH_KEY,
}

internal data class SoterServiceEvidence(
    val expectedUid: Int?,
    val uidSetupReliable: Boolean,
    val vendorSoterStoppedBeforeSuccessfulTransaction: Boolean,
)

internal class SoterAbuseAnalyzer {

    fun analyze(
        keys: List<SoterKeyEvidence>,
        service: SoterServiceEvidence,
    ): List<TeeSoterAnomaly> {
        val parsed = keys.mapNotNull(::parseKey)
        val anomalies = parsed.flatMap(::keyAnomalies).toMutableList()

        val reliableUids = parsed.filter { it.uid != null && it.fieldsReliable }
        if (service.expectedUid != null && service.uidSetupReliable && reliableUids.isNotEmpty() &&
            reliableUids.any { it.uid != service.expectedUid }
        ) {
            anomalies += TeeSoterAnomaly(
                TeeSoterAnomalyKind.UID_MISMATCH,
                "Soter key uid=${reliableUids.mapNotNull { it.uid }.toSet().joinToString(",")} " +
                    "does not match the calling uid=${service.expectedUid}.",
            )
        }

        val cpuIds = parsed
            .filter { it.blobKind == SoterBlobKind.LEGACY && it.fieldsReliable }
            .mapNotNull { it.cpuId?.takeIf(String::isNotBlank) }
            .toSet()
        if (cpuIds.size > 1) {
            anomalies += TeeSoterAnomaly(
                TeeSoterAnomalyKind.CPU_ID_MISMATCH,
                "Soter ASK/AuthKey cpu_id values disagree: ${cpuIds.joinToString(",")}.",
            )
        }

        if (service.vendorSoterStoppedBeforeSuccessfulTransaction) {
            anomalies += TeeSoterAnomaly(
                TeeSoterAnomalyKind.SOFTWARE_HAL_TAKEOVER,
                "init.svc.vendor.soter was exactly stopped immediately before a successful Soter transaction.",
            )
        }
        return anomalies
            .distinctBy { it.kind to it.detail }
            // Keep report order deterministic even if a retry captured multiple attempts.
            .sortedBy { it.kind.ordinal }
    }

    private fun parseKey(evidence: SoterKeyEvidence): ParsedKey? {
        val raw = evidence.rawJson?.takeIf { it.isNotBlank() } ?: return null
        return runCatching {
            val json = JSONObject(raw)
            if (json.has("certs")) {
                parseCertificateKey(json.getJSONArray("certs").optString(0), evidence)
            } else {
                parseLegacyKey(json, evidence)
            }
        }.getOrNull()
    }

    private fun parseLegacyKey(json: JSONObject, evidence: SoterKeyEvidence): ParsedKey {
        val cpuId = json.optString("cpu_id", "")
        val uid = if (json.has("uid")) json.optLong("uid").toInt() else null
        val counter = if (json.has("counter")) json.optLong("counter") else null
        val fieldsReliable = cpuId.isNotBlank() && json.has("uid") && json.has("counter")
        return ParsedKey(
            evidence = evidence,
            blobKind = SoterBlobKind.LEGACY,
            cpuId = cpuId,
            uid = uid,
            counter = counter,
            fieldsReliable = fieldsReliable,
            spkiSha256 = evidence.publicPem?.let(::pemSpkiSha256),
        )
    }

    private fun parseCertificateKey(certificatePem: String, evidence: SoterKeyEvidence): ParsedKey? {
        if (certificatePem.isBlank()) return null
        val certificate = runCatching {
            CertificateFactory.getInstance("X.509")
                .generateCertificate(certificatePem.byteInputStream())
        }.getOrNull() ?: return null
        val raw = evidence.rawJson.orEmpty()
        // The SDK rewrites the JSON after extracting these values. They are reliable only when all
        // three survived parsing; default -1/-1/"" otherwise means the certificate extension failed.
        val json = runCatching { JSONObject(raw) }.getOrNull() ?: return null
        val cpuId = json.optString("cpu_id", "")
        val uid = if (json.has("uid")) json.optInt("uid") else null
        val counter = if (json.has("counter")) json.optLong("counter") else null
        return ParsedKey(
            evidence = evidence,
            blobKind = SoterBlobKind.CERT_CHAIN,
            cpuId = cpuId,
            uid = uid,
            counter = counter,
            fieldsReliable = cpuId.isNotBlank() && uid != null && counter != null,
            spkiSha256 = certificate.publicKey.encoded?.let(::sha256Hex),
        )
    }

    private fun keyAnomalies(key: ParsedKey): List<TeeSoterAnomaly> {
        val anomalies = mutableListOf<TeeSoterAnomaly>()
        key.spkiSha256?.let { fingerprint ->
            when (fingerprint) {
                D_SOTER_FIXED_SPKI_SHA256 -> anomalies += TeeSoterAnomaly(
                    TeeSoterAnomalyKind.D_SOTER_FIXED_SPKI,
                    "Known D-Soter fixed public key matched (SPKI SHA-256 $fingerprint).",
                )

                RELAY_UID_ZERO_SPKI_SHA256 -> anomalies += TeeSoterAnomaly(
                    TeeSoterAnomalyKind.KNOWN_RELAY_SPKI,
                    "Known relay uid=0 ASK key matched (SPKI SHA-256 $fingerprint).",
                )
            }
        }
        if (key.evidence.signatureBase64.orEmpty().isNotBlank()) {
            val signature = runCatching {
                Base64.getDecoder().decode(key.evidence.signatureBase64)
            }.getOrNull()
            if (signature?.size == RSA_2048_SIGNATURE_BYTES && signature.all { it == 0.toByte() }) {
                anomalies += TeeSoterAnomaly(
                    TeeSoterAnomalyKind.D_SOTER_ZERO_SIGNATURE,
                    "Soter signature is exactly 256 zero bytes.",
                )
            }
        }
        if (key.fieldsReliable) {
            if (key.cpuId == D_SOTER_ZERO_CPU_ID) {
                anomalies += TeeSoterAnomaly(
                    TeeSoterAnomalyKind.D_SOTER_ZERO_CPU_ID,
                    "Soter cpu_id is the D-Soter all-zero value.",
                )
            }
            if (key.cpuId == RELAY_CPU_ID) {
                anomalies += TeeSoterAnomaly(
                    TeeSoterAnomalyKind.KNOWN_RELAY_CPU_ID,
                    "Known relay cpu_id $RELAY_CPU_ID matched.",
                )
            }
            if (key.counter != null && key.counter <= 0) {
                anomalies += TeeSoterAnomaly(
                    TeeSoterAnomalyKind.INVALID_COUNTER,
                    "Soter legacy counter=${key.counter} is not positive.",
                )
            }
        }
        return anomalies
    }

    private fun pemSpkiSha256(pem: String): String? {
        val lines = pem.trim().lines()
        if (lines.size < 3) return null
        val encoded = lines.subList(1, lines.lastIndex).joinToString("")
        val der = runCatching {
            Base64.getMimeDecoder().decode(encoded + "=".repeat((4 - encoded.length % 4) % 4))
        }.getOrNull() ?: return null
        return sha256Hex(der)
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private data class ParsedKey(
        val evidence: SoterKeyEvidence,
        val blobKind: SoterBlobKind,
        val cpuId: String?,
        val uid: Int?,
        val counter: Long?,
        val fieldsReliable: Boolean,
        val spkiSha256: String?,
    )

    private enum class SoterBlobKind {
        LEGACY,
        CERT_CHAIN,
    }

    private companion object {
        // D-soter commit 6148e02e returns this fixed placeholder key and all-zero signatures.
        private const val D_SOTER_FIXED_SPKI_SHA256 =
            "944f34afbf46422808152263b7df39a97a69c7bd13245a4267236f50e62ee5b3"
        private const val D_SOTER_ZERO_CPU_ID = "0000000000000000"

        // Sampled from the default relay identity on 2026-10-02; all observed slots shared this cpu_id.
        private const val RELAY_CPU_ID = "090000005171734c42866bea148b21f5"
        private const val RELAY_UID_ZERO_SPKI_SHA256 =
            "26e10bfa8dc72caf67aaf83f4fc17560b4af0e0097dd766b6c448793c69d31cc"
        private const val RSA_2048_SIGNATURE_BYTES = 256
    }
}
