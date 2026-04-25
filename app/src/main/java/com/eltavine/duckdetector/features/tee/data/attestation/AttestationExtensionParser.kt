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

import com.eltavine.duckdetector.features.tee.domain.TeeCertificateItem
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Base64
import java.util.Locale
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject

class AttestationExtensionParser {

    fun parse(
        chain: List<X509Certificate>,
        expectedChallenge: ByteArray,
    ): AttestationSnapshot {
        if (chain.isEmpty()) {
            return emptySnapshot(chain, "Certificate chain is empty")
        }

        val attestationIndex = trustedAttestationIndex(chain)
            ?: return emptySnapshot(chain, "Attestation extension not found")
        val attestationCert = chain[attestationIndex]

        return runCatching {
            val extBytes = unwrapOctetString(attestationCert.getExtensionValue(KEY_ATTESTATION_OID))
            val seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(extBytes))
            val attestationVersion = ASN1Integer.getInstance(seq.getObjectAt(0)).value.toInt()
            val attestationTier =
                mapTier(ASN1Enumerated.getInstance(seq.getObjectAt(1)).value.toInt())
            val keymasterVersion = ASN1Integer.getInstance(seq.getObjectAt(2)).value.toInt()
            val keymasterTier =
                mapTier(ASN1Enumerated.getInstance(seq.getObjectAt(3)).value.toInt())
            val challenge = ASN1OctetString.getInstance(seq.getObjectAt(4)).octets
            val swTags = parseTaggedValues(ASN1Sequence.getInstance(seq.getObjectAt(6)))
            val hwTags = parseTaggedValues(ASN1Sequence.getInstance(seq.getObjectAt(7)))
            val tags = swTags + hwTags

            AttestationSnapshot(
                tier = attestationTier ?: TeeTier.UNKNOWN,
                attestationVersion = attestationVersion,
                keymasterVersion = keymasterVersion,
                attestationTier = attestationTier,
                keymasterTier = keymasterTier,
                challengeVerified = challenge.contentEquals(expectedChallenge),
                challengeSummary = formatChallengeSummary(challenge),
                rootOfTrust = tags[704]?.let(::parseRootOfTrust),
                osVersion = tags[705]?.let { formatOsVersion(ASN1Integer.getInstance(it).value) },
                osPatchLevel = tags[706]?.let {
                    formatPatchLevel(
                        ASN1Integer.getInstance(it).value,
                        false
                    )
                },
                vendorPatchLevel = tags[718]?.let {
                    formatPatchLevel(
                        ASN1Integer.getInstance(it).value,
                        true
                    )
                },
                bootPatchLevel = tags[719]?.let {
                    formatPatchLevel(
                        ASN1Integer.getInstance(it).value,
                        true
                    )
                },
                keyProperties = parseKeyProperties(tags),
                authState = parseAuthState(tags),
                applicationInfo = tags[709]?.let(::parseApplicationInfo)
                    ?: AttestedApplicationInfo(),
                deviceInfo = parseDeviceInfo(tags),
                deviceUniqueAttestation = tags.containsKey(720),
                trustedAttestationIndex = attestationIndex,
                rawCertificates = chain,
                displayCertificates = buildDisplayCertificates(
                    chain = chain,
                    trustedAttestationIndex = attestationIndex,
                ),
            )
        }.getOrElse { throwable ->
            emptySnapshot(chain, throwable.message ?: "Failed to parse attestation extension")
        }
    }

    private fun emptySnapshot(
        chain: List<X509Certificate>,
        errorMessage: String,
    ): AttestationSnapshot {
        return AttestationSnapshot(
            tier = TeeTier.UNKNOWN,
            attestationVersion = null,
            keymasterVersion = null,
            attestationTier = null,
            keymasterTier = null,
            challengeVerified = false,
            challengeSummary = null,
            rootOfTrust = null,
            osVersion = null,
            osPatchLevel = null,
            vendorPatchLevel = null,
            bootPatchLevel = null,
            keyProperties = AttestedKeyProperties(),
            authState = AttestedAuthState(),
            applicationInfo = AttestedApplicationInfo(),
            deviceInfo = AttestedDeviceInfo(),
            deviceUniqueAttestation = false,
            trustedAttestationIndex = null,
            rawCertificates = chain,
            displayCertificates = buildDisplayCertificates(
                chain = chain,
                trustedAttestationIndex = trustedAttestationIndex(chain),
            ),
            errorMessage = errorMessage,
        )
    }

    private fun buildDisplayCertificates(
        chain: List<X509Certificate>,
        trustedAttestationIndex: Int?,
    ): List<TeeCertificateItem> {
        if (trustedAttestationIndex == null) {
            return emptyList()
        }
        return chain.mapIndexed { index, cert ->
            mapCertificate(
                index = index,
                totalCount = chain.size,
                trustedAttestationIndex = trustedAttestationIndex,
                cert = cert,
            )
        }
    }

    private fun parseTaggedValues(sequence: ASN1Sequence): Map<Int, ASN1Encodable> {
        val map = linkedMapOf<Int, ASN1Encodable>()
        sequence.toArray().forEach { encodable ->
            if (encodable is ASN1TaggedObject) {
                map[encodable.tagNo] = encodable.baseObject.toASN1Primitive()
            }
        }
        return map
    }

    private fun parseRootOfTrust(value: ASN1Encodable): RootOfTrustSnapshot? {
        val seq = ASN1Sequence.getInstance(value)
        if (seq.size() < 3) {
            return null
        }
        val verifiedBootKey = ASN1OctetString.getInstance(seq.getObjectAt(0)).octets.toHex()
        val deviceLocked = ASN1Boolean.getInstance(seq.getObjectAt(1)).isTrue
        val verifiedBootState =
            when (ASN1Enumerated.getInstance(seq.getObjectAt(2)).value.toInt()) {
                0 -> "Verified"
                1 -> "Self-signed"
                2 -> "Unverified"
                3 -> "Failed"
                else -> "Unknown"
            }
        val verifiedBootHash = if (seq.size() > 3) {
            ASN1OctetString.getInstance(seq.getObjectAt(3)).octets.toHex()
        } else {
            null
        }
        return RootOfTrustSnapshot(
            verifiedBootKeyHex = verifiedBootKey,
            deviceLocked = deviceLocked,
            verifiedBootState = verifiedBootState,
            verifiedBootHashHex = verifiedBootHash,
        )
    }

    private fun parseDeviceInfo(tags: Map<Int, ASN1Encodable>): AttestedDeviceInfo {
        return AttestedDeviceInfo(
            brand = tags[710]?.let(::parseOctetsAsString),
            device = tags[711]?.let(::parseOctetsAsString),
            product = tags[712]?.let(::parseOctetsAsString),
            serial = tags[713]?.let(::parseOctetsAsString),
            imei = tags[714]?.let(::parseOctetsAsString),
            meid = tags[715]?.let(::parseOctetsAsString),
            manufacturer = tags[716]?.let(::parseOctetsAsString),
            model = tags[717]?.let(::parseOctetsAsString),
            secondImei = tags[723]?.let(::parseOctetsAsString),
        )
    }

    private fun parseKeyProperties(tags: Map<Int, ASN1Encodable>): AttestedKeyProperties {
        val algorithm = tags[2]?.let { mapAlgorithm(ASN1Integer.getInstance(it).value.toInt()) }
        val keySize = tags[3]?.let { ASN1Integer.getInstance(it).value.toInt() }
        val ecCurve = tags[10]?.let { mapEcCurve(ASN1Integer.getInstance(it).value.toInt()) }
        val purposes = tags[1]?.let(::parseRepeatedIntegers).orEmpty().map(::mapPurpose)
        val digests = tags[5]?.let(::parseRepeatedIntegers).orEmpty().map(::mapDigest)
        val paddings = tags[6]?.let(::parseRepeatedIntegers).orEmpty().map(::mapPadding)
        val origin = tags[702]?.let { mapOrigin(ASN1Integer.getInstance(it).value.toInt()) }
        return AttestedKeyProperties(
            algorithm = algorithm,
            keySize = keySize,
            ecCurve = ecCurve,
            purposes = purposes.filter { it != "Unknown" },
            digests = digests.filter { it != "Unknown" },
            paddings = paddings.filter { it != "Unknown" },
            origin = origin,
            rollbackResistant = tags.containsKey(303),
        )
    }

    private fun parseAuthState(tags: Map<Int, ASN1Encodable>): AttestedAuthState {
        val authBits = tags[504]?.let { ASN1Integer.getInstance(it).value.toLong() } ?: 0L
        return AttestedAuthState(
            noAuthRequired = tags[503]?.let { true },
            userAuthTypes = buildList {
                if (authBits and 0x01L != 0L) add("Password")
                if (authBits and 0x02L != 0L) add("Biometric")
                if (authBits and 0x04L != 0L) add("Any")
            },
            authTimeoutSeconds = tags[505]?.let { ASN1Integer.getInstance(it).value.toInt() },
            trustedPresenceRequired = tags.containsKey(507),
            trustedConfirmationRequired = tags.containsKey(508),
            unlockedDeviceRequired = tags.containsKey(509),
        )
    }

    private fun parseApplicationInfo(value: ASN1Encodable): AttestedApplicationInfo {
        val raw = ASN1OctetString.getInstance(value).octets
        return runCatching {
            val seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(raw))
            val packageInfos = ASN1Set.getInstance(seq.getObjectAt(0))
            val signatureDigests = ASN1Set.getInstance(seq.getObjectAt(1))
            AttestedApplicationInfo(
                packageNames = packageInfos.toArray().mapNotNull { entry ->
                    val packageInfo = ASN1Sequence.getInstance(entry)
                    if (packageInfo.size() >= 1) {
                        String(
                            ASN1OctetString.getInstance(packageInfo.getObjectAt(0)).octets,
                            StandardCharsets.UTF_8,
                        )
                    } else {
                        null
                    }
                },
                signatureDigestsSha256 = signatureDigests.toArray().mapNotNull { entry ->
                    runCatching {
                        ASN1OctetString.getInstance(entry).octets.toHex()
                    }.getOrNull()
                },
                rawBytesHex = raw.toHex(),
            )
        }.getOrElse {
            AttestedApplicationInfo(rawBytesHex = raw.toHex())
        }
    }

    private fun parseOctetsAsString(value: ASN1Encodable): String {
        return String(ASN1OctetString.getInstance(value).octets, StandardCharsets.UTF_8)
    }

    private fun mapCertificate(
        index: Int,
        totalCount: Int,
        trustedAttestationIndex: Int,
        cert: X509Certificate,
    ): TeeCertificateItem {
        val dateFormat = SimpleDateFormat("yyyy-MM-dd", Locale.US)
        val publicKeySummary = when (val key = cert.publicKey) {
            is java.security.interfaces.RSAKey -> "${key.modulus.bitLength()}-bit RSA"
            is java.security.interfaces.ECKey -> "${key.params.order.bitLength()}-bit EC"
            else -> key.algorithm
        }
        return TeeCertificateItem(
            slotLabel = when {
                index == trustedAttestationIndex -> "Attestation certificate"
                index == 0 -> "Generated key certificate"
                index == totalCount - 1 -> "Root certificate"
                else -> "Intermediate ${index}"
            },
            subject = prettyDn(cert.subjectX500Principal.name),
            issuer = prettyDn(cert.issuerX500Principal.name),
            serialNumber = cert.serialNumber.toString(16),
            validFrom = dateFormat.format(cert.notBefore),
            validUntil = dateFormat.format(cert.notAfter),
            signatureAlgorithm = cert.sigAlgName,
            publicKeySummary = publicKeySummary,
        )
    }

    private fun prettyDn(input: String): String {
        return Regex("CN=([^,]+)").find(input)?.groupValues?.getOrNull(1) ?: input
    }

    private fun formatPatchLevel(value: BigInteger, includeDay: Boolean): String? {
        val raw = value.toString().padStart(if (includeDay) 8 else 6, '0')
        return when {
            raw.all { it == '0' } -> null
            includeDay && raw.length >= 8 -> "${raw.substring(0, 4)}-${
                raw.substring(
                    4,
                    6
                )
            }-${raw.substring(6, 8)}"

            !includeDay && raw.length >= 6 -> "${raw.substring(0, 4)}-${raw.substring(4, 6)}"
            else -> raw
        }
    }

    private fun formatOsVersion(value: BigInteger): String {
        val raw = value.toString().padStart(6, '0')
        return "${raw.substring(0, 2).trimStart('0').ifBlank { "0" }}." +
                "${raw.substring(2, 4).trimStart('0').ifBlank { "0" }}." +
                raw.substring(4, 6).trimStart('0').ifBlank { "0" }
    }

    private fun formatChallengeSummary(challenge: ByteArray): String {
        return "len=${challenge.size}, sha256=${
            MessageDigest.getInstance("SHA-256").digest(challenge).toHex().take(12)
        }, " +
                "b64=${Base64.getEncoder().encodeToString(challenge).take(18)}"
    }

    private fun unwrapOctetString(data: ByteArray?): ByteArray {
        if (data == null) {
            return ByteArray(0)
        }
        ASN1InputStream(data).use { input ->
            val primitive = input.readObject()
            return ASN1OctetString.getInstance(primitive).octets
        }
    }

    private fun mapTier(value: Int): TeeTier? {
        return when (value) {
            0 -> TeeTier.SOFTWARE
            1 -> TeeTier.TEE
            2 -> TeeTier.STRONGBOX
            else -> TeeTier.UNKNOWN
        }
    }

    private fun mapAlgorithm(value: Int): String = when (value) {
        1 -> "RSA"
        3 -> "EC"
        32 -> "AES"
        128 -> "HMAC"
        else -> "Unknown"
    }

    private fun mapPurpose(value: Int): String = when (value) {
        0 -> "Encrypt"
        1 -> "Decrypt"
        2 -> "Sign"
        3 -> "Verify"
        5 -> "Wrap key"
        6 -> "Agree key"
        7 -> "Attest key"
        else -> "Unknown"
    }

    private fun mapDigest(value: Int): String = when (value) {
        1 -> "MD5"
        2 -> "SHA-1"
        3 -> "SHA-224"
        4 -> "SHA-256"
        5 -> "SHA-384"
        6 -> "SHA-512"
        else -> "Unknown"
    }

    private fun mapPadding(value: Int): String = when (value) {
        1 -> "None"
        2 -> "RSA-OAEP"
        3 -> "RSA-PSS"
        4 -> "RSA-PKCS1-1_5"
        5 -> "PKCS7"
        else -> "Unknown"
    }

    private fun mapEcCurve(value: Int): String = when (value) {
        0 -> "P-224"
        1 -> "P-256"
        2 -> "P-384"
        3 -> "P-521"
        4 -> "Curve25519"
        else -> "Unknown"
    }

    private fun mapOrigin(value: Int): String = when (value) {
        0 -> "Generated"
        1 -> "Derived"
        2 -> "Imported"
        3 -> "Reserved"
        4 -> "Securely imported"
        else -> "Unknown"
    }

    private fun parseRepeatedIntegers(value: ASN1Encodable): List<Int> {
        val primitive = value.toASN1Primitive()
        return when (primitive) {
            is ASN1Set -> primitive.toArray().mapNotNull(::extractInt)
            is ASN1Sequence -> primitive.toArray().mapNotNull(::extractInt)
            else -> listOfNotNull(extractInt(primitive))
        }
    }

    private fun extractInt(value: ASN1Encodable): Int? {
        return when (value) {
            is ASN1Integer -> value.value.toInt()
            is ASN1Enumerated -> value.value.toInt()
            is ASN1ObjectIdentifier -> value.id.toIntOrNull()
            else -> runCatching { ASN1Integer.getInstance(value).value.toInt() }.getOrNull()
        }
    }

    private fun trustedAttestationIndex(chain: List<X509Certificate>): Int? {
        return chain.indices.reversed().firstOrNull { index ->
            hasAttestationExtension(chain[index])
        }
    }

    private fun hasAttestationExtension(certificate: X509Certificate): Boolean {
        return certificate.getExtensionValue(KEY_ATTESTATION_OID) != null
    }

    private fun ByteArray.toHex(): String {
        return joinToString(separator = "") { byte -> "%02x".format(byte) }
    }

    companion object {
        private const val KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
    }
}
