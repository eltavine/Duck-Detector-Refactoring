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

data class GenerateKeyReplyParcelParseResult(
    val parseSucceeded: Boolean,
    val authorizationCount: Int?,
    val lastAuthorizationSecLevel: Long?,
    val lastAuthorizationTag: Long?,
    val lastAuthorizationUnionTag: Long?,
    val lastAuthorizationHasUnknownUnionTag: Boolean,
    val modificationTimeMs: Long?,
    val matched: Boolean = false,
    val rawPrefix: String?,
    val detail: String,
)

private data class AuthorizationSlot(
    val secLevel: Long,
    val tag: Long,
    val unionTag: Long,
    val startOffset: Int,
    val endOffset: Int,
)

class GenerateKeyReplyParcelParser {

    fun parse(rawReply: ByteArray, rawPrefix: String? = null): GenerateKeyReplyParcelParseResult {
        val resolvedRawPrefix = rawPrefix ?: rawReply.toHexPrefix()
        if (rawReply.size < MIN_REPLY_BYTES) {
            return failure(
                rawReply = rawReply,
                rawPrefix = resolvedRawPrefix,
                reason = "reply_too_short",
            )
        }

        return runCatching {
            val exceptionCode = readIntLe(rawReply, 0)
            val authorizationCount = readIntLe(rawReply, AUTHORIZATION_COUNT_OFFSET)

            require(exceptionCode == 0) { "unexpected_exception_code=$exceptionCode" }
            require(authorizationCount in 1..MAX_AUTHORIZATION_COUNT) {
                "authorization_count_out_of_range=$authorizationCount"
            }

            val authorizations = parseAuthorizations(rawReply, authorizationCount)
            val lastAuthorization = authorizations.last()
            val metadataTail = parseMetadataTail(rawReply, lastAuthorization.endOffset)
            val modificationTimeMs = metadataTail.modificationTimeMs

            val lastAuthorizationHasUnknownUnionTag = isUnknownKeyParameterValueUnionTag(lastAuthorization.unionTag)
            val matched =
                modificationTimeMs == TARGET_MODIFICATION_TIME_MS &&
                    lastAuthorization.secLevel in TARGET_LAST_AUTHORIZATION_SEC_LEVELS &&
                    lastAuthorization.tag == TARGET_LAST_AUTHORIZATION_TAG &&
                    lastAuthorization.unionTag == TARGET_LAST_AUTHORIZATION_UNION_TAG &&
                    lastAuthorizationHasUnknownUnionTag
            GenerateKeyReplyParcelParseResult(
                parseSucceeded = true,
                authorizationCount = authorizationCount,
                lastAuthorizationSecLevel = lastAuthorization.secLevel,
                lastAuthorizationTag = lastAuthorization.tag,
                lastAuthorizationUnionTag = lastAuthorization.unionTag,
                lastAuthorizationHasUnknownUnionTag = lastAuthorizationHasUnknownUnionTag,
                modificationTimeMs = modificationTimeMs,
                matched = matched,
                rawPrefix = resolvedRawPrefix,
                detail = buildDetail(
                    parseSucceeded = true,
                    reason = "ok",
                    rawSize = rawReply.size,
                    rawPrefix = resolvedRawPrefix,
                    exceptionCode = exceptionCode,
                    authorizationCount = authorizationCount,
                    lastAuthorizationSecLevel = lastAuthorization.secLevel,
                    lastAuthorizationTag = lastAuthorization.tag,
                    lastAuthorizationUnionTag = lastAuthorization.unionTag,
                    lastAuthorizationHasUnknownUnionTag = lastAuthorizationHasUnknownUnionTag,
                    modificationTimeMs = modificationTimeMs,
                    finalOffset = metadataTail.modificationTimeOffset + Long.SIZE_BYTES,
                    certificateLength = metadataTail.certificateLength,
                    certificateChainLength = metadataTail.certificateChainLength,
                    matched = matched,
                ),
            )
        }.getOrElse { throwable ->
            failure(
                rawReply = rawReply,
                rawPrefix = resolvedRawPrefix,
                reason = throwable.message ?: throwable.javaClass.simpleName,
            )
        }
    }

    private fun failure(
        rawReply: ByteArray,
        rawPrefix: String?,
        reason: String,
    ): GenerateKeyReplyParcelParseResult {
        return GenerateKeyReplyParcelParseResult(
            parseSucceeded = false,
            authorizationCount = null,
            lastAuthorizationSecLevel = null,
            lastAuthorizationTag = null,
            lastAuthorizationUnionTag = null,
            lastAuthorizationHasUnknownUnionTag = false,
            modificationTimeMs = null,
            matched = false,
            rawPrefix = rawPrefix,
            detail = buildDetail(
                parseSucceeded = false,
                reason = reason,
                rawSize = rawReply.size,
                rawPrefix = rawPrefix,
            ),
        )
    }

    private fun buildDetail(
        parseSucceeded: Boolean,
        reason: String,
        rawSize: Int,
        rawPrefix: String?,
        exceptionCode: Int? = null,
        authorizationCount: Int? = null,
        lastAuthorizationSecLevel: Long? = null,
        lastAuthorizationTag: Long? = null,
        lastAuthorizationUnionTag: Long? = null,
        lastAuthorizationHasUnknownUnionTag: Boolean? = null,
        modificationTimeMs: Long? = null,
        finalOffset: Int? = null,
        certificateLength: Int? = null,
        certificateChainLength: Int? = null,
        matched: Boolean? = null,
    ): String {
        return listOf(
            "parseSucceeded=$parseSucceeded",
            "reason=$reason",
            "rawSize=$rawSize",
            "rawPrefix=${rawPrefix ?: "null"}",
            "exceptionCode=${exceptionCode ?: "null"}",
            "authorizationCount=${authorizationCount ?: "null"}",
            "lastAuthorizationSecLevel=${lastAuthorizationSecLevel ?: "null"}",
            "lastAuthorizationTag=${lastAuthorizationTag ?: "null"}",
            "lastAuthorizationUnionTag=${lastAuthorizationUnionTag ?: "null"}",
            "lastAuthorizationHasUnknownUnionTag=${lastAuthorizationHasUnknownUnionTag ?: "null"}",
            "modificationTimeMs=${modificationTimeMs ?: "null"}",
            "finalOffset=${finalOffset ?: "null"}",
            "certificateLength=${certificateLength ?: "null"}",
            "certificateChainLength=${certificateChainLength ?: "null"}",
            "matched=${matched ?: "null"}",
        ).joinToString(separator = ";")
    }

    private fun parseAuthorizations(rawReply: ByteArray, authorizationCount: Int): List<AuthorizationSlot> {
        var offset = AUTHORIZATION_LOGICAL_START_OFFSET
        return buildList {
            repeat(authorizationCount) {
                val startOffset = offset
                require(offset + AUTHORIZATION_HEADER_BYTES <= rawReply.size) {
                    "authorization_block_truncated"
                }
                val secLevel = readUnsignedIntLe(rawReply, offset)
                val tag = readUnsignedIntLe(rawReply, offset + AUTHORIZATION_TAG_OFFSET)
                val unionTag = readUnsignedIntLe(rawReply, offset + AUTHORIZATION_UNION_TAG_OFFSET)
                offset += AUTHORIZATION_HEADER_BYTES
                offset += keyParameterValuePayloadSize(rawReply, offset, unionTag)
                offset = alignToParcelWord(offset)
                add(
                    AuthorizationSlot(
                        secLevel = secLevel,
                        tag = tag,
                        unionTag = unionTag,
                        startOffset = startOffset,
                        endOffset = offset,
                    ),
                )
            }
        }
    }

    private fun isUnknownKeyParameterValueUnionTag(unionTag: Long): Boolean = unionTag !in KNOWN_KEY_PARAMETER_VALUE_UNION_TAGS

    private fun parseMetadataTail(rawReply: ByteArray, authorizationEndOffset: Int): MetadataTail {
        val certificatePresenceOffset = authorizationEndOffset
        require(certificatePresenceOffset + INT_SIZE_BYTES <= rawReply.size) {
            "certificate_field_out_of_bounds"
        }
        val certificatePresent = readIntLe(rawReply, certificatePresenceOffset) != 0
        var offset = certificatePresenceOffset + INT_SIZE_BYTES
        val certificateLength = if (certificatePresent) {
            readByteArrayLength(rawReply, offset).also { length ->
                offset = skipByteArray(rawReply, offset, length, "certificate")
            }
        } else {
            0
        }

        require(offset + INT_SIZE_BYTES <= rawReply.size) {
            "certificate_chain_field_out_of_bounds"
        }
        val certificateChainPresent = readIntLe(rawReply, offset) != 0
        offset += INT_SIZE_BYTES
        val certificateChainLength = if (certificateChainPresent) {
            readByteArrayLength(rawReply, offset).also { length ->
                offset = skipByteArray(rawReply, offset, length, "certificate_chain")
            }
        } else {
            0
        }

        val modificationTimeOffset = alignToParcelWord(offset)
        require(modificationTimeOffset + Long.SIZE_BYTES <= rawReply.size) {
            "modification_time_out_of_bounds"
        }
        return MetadataTail(
            certificateLength = certificateLength,
            certificateChainLength = certificateChainLength,
            modificationTimeMs = readLongLe(rawReply, modificationTimeOffset),
            modificationTimeOffset = modificationTimeOffset,
        )
    }

    private fun keyParameterValuePayloadSize(rawReply: ByteArray, offset: Int, unionTag: Long): Int {
        return when (unionTag) {
            in INT_LIKE_KEY_PARAMETER_VALUE_UNION_TAGS -> INT_SIZE_BYTES
            in LONG_LIKE_KEY_PARAMETER_VALUE_UNION_TAGS -> Long.SIZE_BYTES
            BLOB_KEY_PARAMETER_VALUE_UNION_TAG -> {
                val length = readByteArrayLength(rawReply, offset)
                skipByteArray(rawReply, offset, length, "key_parameter_blob") - offset
            }
            else -> 0
        }
    }

    private fun readIntLe(bytes: ByteArray, offset: Int): Int {
        require(offset >= 0 && offset + 4 <= bytes.size) { "int_out_of_bounds@$offset" }
        return (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)
    }

    private fun readUnsignedIntLe(bytes: ByteArray, offset: Int): Long = readIntLe(bytes, offset).toLong() and 0xFFFFFFFFL

    private fun readByteArrayLength(bytes: ByteArray, offset: Int): Int {
        val length = readIntLe(bytes, offset)
        require(length >= 0) { "byte_array_length_negative=$length" }
        return length
    }

    private fun skipByteArray(bytes: ByteArray, offset: Int, length: Int, label: String): Int {
        val dataOffset = offset + INT_SIZE_BYTES
        val endOffset = dataOffset + length
        require(endOffset <= bytes.size) { "${label}_truncated" }
        return alignToParcelWord(endOffset)
    }

    private fun readLongLe(bytes: ByteArray, offset: Int): Long {
        require(offset >= 0 && offset + Long.SIZE_BYTES <= bytes.size) { "long_out_of_bounds@$offset" }
        return (0 until Long.SIZE_BYTES).fold(0L) { acc, index ->
            acc or ((bytes[offset + index].toLong() and 0xFFL) shl (index * 8))
        }
    }

    private fun alignToParcelWord(offset: Int): Int {
        return (offset + PARCEL_WORD_MASK) and PARCEL_WORD_MASK.inv()
    }

    private fun ByteArray.toHexPrefix(maxBytes: Int = DEFAULT_PREFIX_BYTES): String {
        return take(maxBytes).joinToString(" ") { "%02X".format(it.toInt() and 0xFF) }
    }

    private data class MetadataTail(
        val certificateLength: Int,
        val certificateChainLength: Int,
        val modificationTimeMs: Long,
        val modificationTimeOffset: Int,
    )

    private companion object {
        const val DEFAULT_PREFIX_BYTES = 32
        const val INT_SIZE_BYTES = 4
        const val PARCEL_WORD_MASK = INT_SIZE_BYTES - 1
        const val MAX_AUTHORIZATION_COUNT = 256
        const val MIN_REPLY_BYTES = 48
        const val AUTHORIZATION_COUNT_OFFSET = 44
        const val AUTHORIZATION_LOGICAL_START_OFFSET = 48
        const val AUTHORIZATION_HEADER_BYTES = 12
        const val AUTHORIZATION_TAG_OFFSET = 4
        const val AUTHORIZATION_UNION_TAG_OFFSET = 8
        const val TARGET_MODIFICATION_TIME_MS = 4294967297L
        val TARGET_LAST_AUTHORIZATION_SEC_LEVELS = setOf(4L, 256L)
        const val TARGET_LAST_AUTHORIZATION_TAG = 0x00000001L
        const val TARGET_LAST_AUTHORIZATION_UNION_TAG = 32L
        val KNOWN_KEY_PARAMETER_VALUE_UNION_TAGS = (0L..14L).toSet()
        val INT_LIKE_KEY_PARAMETER_VALUE_UNION_TAGS = setOf(1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L, 9L, 10L, 11L)
        val LONG_LIKE_KEY_PARAMETER_VALUE_UNION_TAGS = setOf(12L, 13L)
        const val BLOB_KEY_PARAMETER_VALUE_UNION_TAG = 14L
    }
}
