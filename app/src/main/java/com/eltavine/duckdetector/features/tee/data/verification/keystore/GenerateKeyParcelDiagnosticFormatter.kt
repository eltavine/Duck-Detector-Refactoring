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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import java.util.Locale

internal object GenerateKeyParcelDiagnosticFormatter {

    fun format(
        rawRequest: ByteArray?,
        rawReply: ByteArray?,
        parseResult: GenerateKeyReplyParcelParseResult?,
        captureDetail: String,
    ): String {
        return buildString {
            appendLine("=== [GENERATEKEY transaction atomic structure dump] ===")
            appendLine("captureDetail=$captureDetail")
            appendLine()
            appendRequest(rawRequest)
            appendLine()
            appendReply(rawReply, parseResult)
        }.trimEnd()
    }

    private fun StringBuilder.appendRequest(rawRequest: ByteArray?) {
        appendLine("--- [Request Data Parse] ---")
        if (rawRequest == null) {
            appendLine("  Request parcel unavailable.")
            return
        }
        appendLine("  (length: ${rawRequest.size} bytes)")
        runCatching {
            val header = rawRequest.readIntLe(0)
            appendLine("  Offset: 0x0000-0x0004 | interface header: $header")
            val token = rawRequest.readParcelString(4)
            appendLine(
                "  Offset: ${token.range()} | interface descriptor: ${token.value ?: "null"}"
            )
        }.getOrElse { throwable ->
            appendLine("  [!] Request parse interrupted: ${throwable.message ?: throwable.javaClass.simpleName}")
        }
        appendLine("--- [Request Raw Hex] ---")
        appendLine(rawRequest.toHexDump())
    }

    private fun StringBuilder.appendReply(
        rawReply: ByteArray?,
        parseResult: GenerateKeyReplyParcelParseResult?,
    ) {
        appendLine("--- [Reply Data Parse] ---")
        if (rawReply == null) {
            appendLine("  Reply parcel unavailable.")
            return
        }
        appendLine("  --- [Parcel raw binary sequence] ---")
        appendLine("  (length: ${rawReply.size} bytes)")
        val parsed = parseReplyForDiagnostic(rawReply)
        if (parsed == null) {
            val reason = parseResult?.detail ?: "reply parse unavailable"
            appendLine("  [!] Reply parse interrupted: $reason")
        } else {
            appendLine(
                "  Offset: 0x0000-0x0004 | exception header: ${parsed.exceptionCode} " +
                    "(${if (parsed.exceptionCode == 0) "SUCCESS" else "ERROR"})"
            )
            if (parsed.exceptionCode == 0) {
                appendLine("  [KeyMetadata return value parse]:")
                appendLine("    Offset: 0x0004 | [KeyMetadata structure start]")
                appendLine("      [Field] key (KeyDescriptor):")
                appendLine("        Offset: 0x0004-0x0028 | Descriptor block: 40 bytes")
                appendLine(
                    "      Offset: 0x0028-0x002C | keySecurityLevel: " +
                        "${rawReply.readUnsignedIntLe(KEY_SECURITY_LEVEL_OFFSET)}"
                )
                appendLine("      Offset: 0x002C | authorizations (Authorization[]):")
                appendLine("        Count: ${parsed.authorizations.size}")
                parsed.authorizations.forEachIndexed { index, authorization ->
                    appendAuthorization(index, authorization)
                }
                appendLine("      [Field] certificate: ${parsed.certificateLength} bytes")
                appendLine("      [Field] certificateChain: ${parsed.certificateChainLength} bytes")
                appendLine("      [Field] modificationTimeMs: ${parsed.modificationTimeMs}")
            } else {
                appendLine("  [!] Transaction failed; no KeyMetadata body parsed.")
            }
        }
        appendFingerprintTuple(parseResult)
        appendLine("--- [Reply Raw Hex] ---")
        appendLine(rawReply.toHexDump())
    }

    private fun StringBuilder.appendAuthorization(
        index: Int,
        authorization: DiagnosticAuthorization,
    ) {
        appendLine("          [$index] Authorization:")
        appendLine("            SecLevel: ${authorization.secLevel}")
        appendLine(
            "            Tag: 0x${authorization.tag.toHexWord()} " +
                "(ID=${authorization.tag and KEYMASTER_TAG_ID_MASK}, Type=${authorization.tag ushr KEYMASTER_TAG_TYPE_SHIFT})"
        )
        appendLine("              UnionTag (member index): ${authorization.unionTag}")
        authorization.valueLine?.let {
            appendLine("              $it")
        }
        if (authorization.unknownUnionTag) {
            appendLine("              [!] Unknown UnionTag: ${authorization.unionTag}")
        }
        appendLine("            Offset: ${formatOffsetRange(authorization.startOffset, authorization.endOffset)}")
    }

    private fun StringBuilder.appendFingerprintTuple(parseResult: GenerateKeyReplyParcelParseResult?) {
        appendLine("  [Fingerprint tuple]:")
        if (parseResult == null) {
            appendLine("    parserResult: unavailable")
            return
        }
        appendLine("    modificationTimeMs: ${parseResult.modificationTimeMs}")
        appendLine("    last Authorization SecLevel: ${parseResult.lastAuthorizationSecLevel}")
        appendLine("    last Authorization UnionTag: ${parseResult.lastAuthorizationUnionTag}")
        appendLine("    last UnionTag unknown/non-standard: ${parseResult.lastAuthorizationHasUnknownUnionTag}")
        appendLine("    matched: ${parseResult.matched}")
    }

    private fun parseReplyForDiagnostic(rawReply: ByteArray): DiagnosticReply? {
        return runCatching {
            val exceptionCode = rawReply.readIntLe(0)
            if (exceptionCode != 0) {
                return@runCatching DiagnosticReply(exceptionCode = exceptionCode)
            }
            val authorizationCount = rawReply.readIntLe(AUTHORIZATION_COUNT_OFFSET)
            require(authorizationCount in 0..MAX_AUTHORIZATION_COUNT) {
                "authorization_count_out_of_range=$authorizationCount"
            }
            var offset = AUTHORIZATION_START_OFFSET
            val authorizations = buildList {
                repeat(authorizationCount) {
                    val startOffset = offset
                    val secLevel = rawReply.readUnsignedIntLe(offset)
                    val tag = rawReply.readUnsignedIntLe(offset + AUTHORIZATION_TAG_OFFSET)
                    val unionTag = rawReply.readUnsignedIntLe(offset + AUTHORIZATION_UNION_TAG_OFFSET)
                    offset += AUTHORIZATION_HEADER_BYTES
                    val value = readDiagnosticUnionValue(rawReply, offset, unionTag)
                    offset += value.payloadSize
                    offset = alignToParcelWord(offset)
                    add(
                        DiagnosticAuthorization(
                            secLevel = secLevel,
                            tag = tag,
                            unionTag = unionTag,
                            valueLine = value.valueLine,
                            unknownUnionTag = unionTag !in KNOWN_UNION_TAGS,
                            startOffset = startOffset,
                            endOffset = offset,
                        )
                    )
                }
            }
            val certificate = rawReply.readNullableByteArray(offset, "certificate")
            offset = certificate.endOffset
            val certificateChain = rawReply.readNullableByteArray(offset, "certificateChain")
            offset = certificateChain.endOffset
            val modificationTimeOffset = alignToParcelWord(offset)
            val modificationTimeMs = rawReply.readLongLe(modificationTimeOffset)
            DiagnosticReply(
                exceptionCode = exceptionCode,
                authorizations = authorizations,
                certificateLength = certificate.length,
                certificateChainLength = certificateChain.length,
                modificationTimeMs = modificationTimeMs,
            )
        }.getOrNull()
    }

    private fun readDiagnosticUnionValue(
        bytes: ByteArray,
        offset: Int,
        unionTag: Long,
    ): DiagnosticUnionValue {
        return when (unionTag) {
            in INT_LIKE_UNION_TAGS -> {
                val intValue = bytes.readIntLe(offset)
                DiagnosticUnionValue(
                    payloadSize = INT_SIZE_BYTES,
                    valueLine = "Value (Int/Enum): $intValue",
                )
            }
            BOOL_UNION_TAG -> {
                val boolValue = bytes.readIntLe(offset) != 0
                DiagnosticUnionValue(
                    payloadSize = INT_SIZE_BYTES,
                    valueLine = "Value (Boolean): $boolValue",
                )
            }
            in LONG_LIKE_UNION_TAGS -> {
                val longValue = bytes.readLongLe(offset)
                DiagnosticUnionValue(
                    payloadSize = Long.SIZE_BYTES,
                    valueLine = "Value (Long/Date): $longValue",
                )
            }
            BLOB_UNION_TAG -> {
                val length = bytes.readIntLe(offset)
                require(length >= 0) { "blob_length_negative=$length" }
                val dataOffset = offset + INT_SIZE_BYTES
                val endOffset = dataOffset + length
                require(endOffset <= bytes.size) { "blob_truncated" }
                val blob = bytes.copyOfRange(dataOffset, endOffset)
                DiagnosticUnionValue(
                    payloadSize = alignToParcelWord(endOffset) - offset,
                    valueLine = buildString {
                        append("Value (Blob): ")
                        append(length)
                        append(" bytes")
                        if (blob.isNotEmpty() && blob.size <= INLINE_BLOB_HEX_BYTES) {
                            append(" | Hex: ")
                            append(blob.toHexCompact())
                        }
                    },
                )
            }
            else -> DiagnosticUnionValue(payloadSize = 0, valueLine = null)
        }
    }

    private fun ByteArray.readNullableByteArray(offset: Int, label: String): DiagnosticByteArray {
        val presence = readIntLe(offset)
        var cursor = offset + INT_SIZE_BYTES
        if (presence == 0) {
            return DiagnosticByteArray(length = 0, endOffset = cursor)
        }
        val length = readIntLe(cursor)
        require(length >= 0) { "${label}_length_negative=$length" }
        cursor += INT_SIZE_BYTES
        val endOffset = cursor + length
        require(endOffset <= size) { "${label}_truncated" }
        return DiagnosticByteArray(
            length = length,
            endOffset = alignToParcelWord(endOffset),
        )
    }

    private fun ByteArray.readParcelString(offset: Int): ParcelString {
        val length = readIntLe(offset)
        if (length < 0) {
            return ParcelString(value = null, startOffset = offset, endOffset = offset + INT_SIZE_BYTES)
        }
        val charsOffset = offset + INT_SIZE_BYTES
        val terminatorOffset = charsOffset + (length * Char.SIZE_BYTES)
        require(terminatorOffset + Char.SIZE_BYTES <= size) { "string_truncated@$offset" }
        val chars = CharArray(length) { index ->
            val charOffset = charsOffset + (index * Char.SIZE_BYTES)
            val code = (this[charOffset].toInt() and 0xFF) or
                ((this[charOffset + 1].toInt() and 0xFF) shl Byte.SIZE_BITS)
            code.toChar()
        }
        val endOffset = alignToParcelWord(terminatorOffset + Char.SIZE_BYTES)
        return ParcelString(
            value = chars.concatToString(),
            startOffset = offset,
            endOffset = endOffset,
        )
    }

    private fun ByteArray.readIntLe(offset: Int): Int {
        require(offset >= 0 && offset + INT_SIZE_BYTES <= size) { "int_out_of_bounds@$offset" }
        return (this[offset].toInt() and 0xFF) or
            ((this[offset + 1].toInt() and 0xFF) shl 8) or
            ((this[offset + 2].toInt() and 0xFF) shl 16) or
            ((this[offset + 3].toInt() and 0xFF) shl 24)
    }

    private fun ByteArray.readUnsignedIntLe(offset: Int): Long = readIntLe(offset).toLong() and 0xFFFFFFFFL

    private fun ByteArray.readLongLe(offset: Int): Long {
        require(offset >= 0 && offset + Long.SIZE_BYTES <= size) { "long_out_of_bounds@$offset" }
        return (0 until Long.SIZE_BYTES).fold(0L) { acc, index ->
            acc or ((this[offset + index].toLong() and 0xFFL) shl (index * Byte.SIZE_BITS))
        }
    }

    private fun ByteArray.toHexDump(bytesPerLine: Int = HEX_BYTES_PER_LINE): String {
        if (isEmpty()) {
            return ""
        }
        return asList()
            .chunked(bytesPerLine)
            .joinToString(separator = "\n") { line ->
                line.joinToString(separator = " ") { "%02X".format(Locale.US, it.toInt() and 0xFF) }
            }
    }

    private fun ByteArray.toHexCompact(): String {
        return joinToString(separator = "") { "%02X".format(Locale.US, it.toInt() and 0xFF) }
    }

    private fun Long.toHexWord(): String = "%08X".format(Locale.US, this and 0xFFFFFFFFL)

    private fun ParcelString.range(): String = formatOffsetRange(startOffset, endOffset)

    private fun formatOffsetRange(startOffset: Int, endOffset: Int): String {
        return "0x%04X-0x%04X".format(Locale.US, startOffset, endOffset)
    }

    private fun alignToParcelWord(offset: Int): Int {
        return (offset + PARCEL_WORD_MASK) and PARCEL_WORD_MASK.inv()
    }

    private data class ParcelString(
        val value: String?,
        val startOffset: Int,
        val endOffset: Int,
    )

    private data class DiagnosticReply(
        val exceptionCode: Int,
        val authorizations: List<DiagnosticAuthorization> = emptyList(),
        val certificateLength: Int = 0,
        val certificateChainLength: Int = 0,
        val modificationTimeMs: Long? = null,
    )

    private data class DiagnosticAuthorization(
        val secLevel: Long,
        val tag: Long,
        val unionTag: Long,
        val valueLine: String?,
        val unknownUnionTag: Boolean,
        val startOffset: Int,
        val endOffset: Int,
    )

    private data class DiagnosticUnionValue(
        val payloadSize: Int,
        val valueLine: String?,
    )

    private data class DiagnosticByteArray(
        val length: Int,
        val endOffset: Int,
    )

    private const val INT_SIZE_BYTES = 4
    private const val PARCEL_WORD_MASK = INT_SIZE_BYTES - 1
    private const val HEX_BYTES_PER_LINE = 16
    private const val INLINE_BLOB_HEX_BYTES = 64
    private const val KEY_SECURITY_LEVEL_OFFSET = 40
    private const val AUTHORIZATION_COUNT_OFFSET = 44
    private const val AUTHORIZATION_START_OFFSET = 48
    private const val AUTHORIZATION_HEADER_BYTES = 12
    private const val AUTHORIZATION_TAG_OFFSET = 4
    private const val AUTHORIZATION_UNION_TAG_OFFSET = 8
    private const val MAX_AUTHORIZATION_COUNT = 256
    private const val KEYMASTER_TAG_ID_MASK = 0x0FFFFFFFL
    private const val KEYMASTER_TAG_TYPE_SHIFT = 28
    private const val BOOL_UNION_TAG = 10L
    private const val BLOB_UNION_TAG = 14L
    private val KNOWN_UNION_TAGS = (0L..14L).toSet()
    private val INT_LIKE_UNION_TAGS = setOf(1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L, 9L, 11L)
    private val LONG_LIKE_UNION_TAGS = setOf(12L, 13L)
}
