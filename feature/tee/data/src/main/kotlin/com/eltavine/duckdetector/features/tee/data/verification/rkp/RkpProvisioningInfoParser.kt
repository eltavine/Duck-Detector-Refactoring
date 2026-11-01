package com.eltavine.duckdetector.features.tee.data.verification.rkp

import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive

/** Decodes only the extension payload; certificate authentication belongs to [RkpExtensionAnalyzer]. */
internal class RkpProvisioningInfoParser {
    fun parse(extension: ByteArray): RkpProvisioningInfo {
        if (extension.size > MAX_EXTENSION_BYTES) {
            return RkpProvisioningInfo(issue = "Provisioning info exceeded the 64 KiB decoding limit.")
        }
        val map = try {
            val wrapped = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(extension))
            // X509Extension.getExtensionValue promises DER, whereas the ASN.1 decoder also accepts BER.
            require(extension.contentEquals(wrapped.getEncoded(ASN1Encoding.DER)))
            val payload = wrapped.octets
            // Defaults reject duplicate keys and trailing data and leave shared references unresolved.
            CBORObject.DecodeFromBytes(payload).also {
                require(!it.isTagged && it.type == CBORType.Map)
            }
        } catch (_: Exception) {
            return RkpProvisioningInfo(issue = "Provisioning info could not be decoded as a DER-wrapped CBOR map.")
        }
        val issues = mutableListOf<String>()
        fun field(key: Int): CBORObject? = map[CBORObject.FromObject(key)]
        fun text(key: Int): String? {
            val value = field(key) ?: return null
            if (value.isTagged || value.type != CBORType.TextString) {
                issues += "Provisioning key $key was not a text string."
                return null
            }
            return value.AsString()
        }
        val countField = field(1)
        if (countField == null) issues += "Required provisioning key 1 was absent."
        val count = countField?.let { value ->
            val number = if (!value.isTagged && value.type == CBORType.Integer && value.CanValueFitInInt64()) {
                value.AsInt64Value()
            } else null
            if (number == null || number !in 0..Int.MAX_VALUE.toLong()) {
                issues += "Provisioning key 1 was not a non-negative supported certificate count."
                null
            } else number.toInt()
        }
        // Key 5 is observed in RKP certificates, but its nested schema and APPROVED/NOT_APPROVED
        // meanings remain undocumented: https://issuetracker.google.com/issues/566467877
        // Preserve diagnostic notation without assigning CTS semantics or inferring an RKP version.
        val metadata = field(5)?.let { value ->
            // The library's diagnostic renderer silently elides deep collections. Report our own
            // display limit explicitly so omitted nested values cannot look like complete evidence.
            if (value.exceedsDisplayDepth()) {
                issues += "Provisioning key 5 exceeded the $MAX_DISPLAY_DEPTH-level display nesting limit."
                null
            } else {
                val diagnostic = value.toString()
                if (diagnostic.length > MAX_METADATA_CHARACTERS) {
                    issues += "Provisioning key 5 display was truncated at $MAX_METADATA_CHARACTERS characters."
                    diagnostic.take(MAX_METADATA_CHARACTERS) + "…"
                } else diagnostic
            }
        }
        val manufacturer = text(3)
        val entity = text(4)
        if (field(4) == null) issues += "Required provisioning key 4 was absent."
        return RkpProvisioningInfo(
            certsIssued = count,
            manufacturer = manufacturer,
            validatedEntity = entity,
            buildMetadata = metadata,
            issue = issues.takeIf { it.isNotEmpty() }?.joinToString(" "),
        )
    }

    private fun CBORObject.exceedsDisplayDepth(depth: Int = 0): Boolean = when (type) {
        CBORType.Array -> depth >= MAX_DISPLAY_DEPTH ||
            (0 until size()).any { this[it].exceedsDisplayDepth(depth + 1) }
        CBORType.Map -> depth >= MAX_DISPLAY_DEPTH || entries.any {
            it.key.exceedsDisplayDepth(depth + 1) || it.value.exceedsDisplayDepth(depth + 1)
        }
        else -> false
    }

    private companion object {
        const val MAX_EXTENSION_BYTES = 64 * 1024
        const val MAX_METADATA_CHARACTERS = 8192
        const val MAX_DISPLAY_DEPTH = 32
    }
}

internal data class RkpProvisioningInfo(
    val certsIssued: Int? = null,
    val manufacturer: String? = null,
    val validatedEntity: String? = null,
    val buildMetadata: String? = null,
    val issue: String? = null,
)
