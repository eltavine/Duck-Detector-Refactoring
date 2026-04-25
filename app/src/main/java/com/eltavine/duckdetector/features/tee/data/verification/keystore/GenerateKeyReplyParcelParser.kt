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
    val rawPrefix: String?,
    val detail: String,
)

private data class AuthorizationSlot(
    val secLevel: Long,
    val tag: Long,
    val unionTag: Long,
    val valueWord: Long,
    val startOffset: Int,
) {
    val endOffset: Int = startOffset + 16
}

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

            val lastAuthorization = parseLastAuthorization(rawReply, authorizationCount)
            require(rawReply.size >= lastAuthorization.endOffset) {
                "authorization_block_truncated"
            }

            val modificationTimeMs = findModificationTimeSignature(rawReply, lastAuthorization.endOffset)

            val lastAuthorizationHasUnknownUnionTag = isUnknownKeyParameterValueUnionTag(lastAuthorization.unionTag)
            GenerateKeyReplyParcelParseResult(
                parseSucceeded = true,
                authorizationCount = authorizationCount,
                lastAuthorizationSecLevel = lastAuthorization.secLevel,
                lastAuthorizationTag = lastAuthorization.tag,
                lastAuthorizationUnionTag = lastAuthorization.unionTag,
                lastAuthorizationHasUnknownUnionTag = lastAuthorizationHasUnknownUnionTag,
                modificationTimeMs = modificationTimeMs,
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
                    finalOffset = lastAuthorization.endOffset,
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
        ).joinToString(separator = ";")
    }

    private fun parseLastAuthorization(rawReply: ByteArray, authorizationCount: Int): AuthorizationSlot {
        val lastAuthorizationOffset = AUTHORIZATION_LOGICAL_START_OFFSET + ((authorizationCount - 1) * AUTHORIZATION_SLOT_SIZE)
        require(rawReply.size >= lastAuthorizationOffset + AUTHORIZATION_SLOT_SIZE) {
            "authorization_block_truncated"
        }
        return AuthorizationSlot(
            secLevel = readUnsignedIntLe(rawReply, lastAuthorizationOffset),
            tag = readUnsignedIntLe(rawReply, lastAuthorizationOffset + AUTHORIZATION_TAG_OFFSET),
            unionTag = readUnsignedIntLe(rawReply, lastAuthorizationOffset + AUTHORIZATION_UNION_TAG_OFFSET),
            valueWord = readUnsignedIntLe(rawReply, lastAuthorizationOffset + AUTHORIZATION_VALUE_OFFSET),
            startOffset = lastAuthorizationOffset,
        )
    }

    private fun isUnknownKeyParameterValueUnionTag(unionTag: Long): Boolean = unionTag !in KNOWN_KEY_PARAMETER_VALUE_UNION_TAGS

    private fun readIntLe(bytes: ByteArray, offset: Int): Int {
        require(offset >= 0 && offset + 4 <= bytes.size) { "int_out_of_bounds@$offset" }
        return (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)
    }

    private fun readUnsignedIntLe(bytes: ByteArray, offset: Int): Long = readIntLe(bytes, offset).toLong() and 0xFFFFFFFFL

    private fun findModificationTimeSignature(rawReply: ByteArray, startOffset: Int): Long? {
        val searchStart = startOffset.coerceAtLeast(0)
        val searchEndExclusive = findFirstDerOffset(rawReply, searchStart) ?: rawReply.size
        var offset = searchStart
        while (offset + MODIFICATION_TIME_SIGNATURE_PREFIX.size <= searchEndExclusive) {
            if (matchesSignature(rawReply, offset, MODIFICATION_TIME_SIGNATURE_PREFIX)) {
                return TARGET_MODIFICATION_TIME_MS
            }
            offset += INT_SIZE_BYTES
        }
        return null
    }

    private fun matchesSignature(bytes: ByteArray, offset: Int, signature: ByteArray): Boolean {
        return signature.indices.all { index -> bytes[offset + index] == signature[index] }
    }

    private fun findFirstDerOffset(rawReply: ByteArray, startOffset: Int): Int? {
        var offset = startOffset
        while (offset + 1 < rawReply.size) {
            if ((rawReply[offset].toInt() and 0xFF) == DER_SEQUENCE_PREFIX_0 &&
                (rawReply[offset + 1].toInt() and 0xFF) == DER_SEQUENCE_PREFIX_1
            ) {
                return offset
            }
            offset += INT_SIZE_BYTES
        }
        return null
    }

    private fun readLongLe(bytes: ByteArray, offset: Int): Long {
        require(offset >= 0 && offset + Long.SIZE_BYTES <= bytes.size) { "long_out_of_bounds@$offset" }
        return (0 until Long.SIZE_BYTES).fold(0L) { acc, index ->
            acc or ((bytes[offset + index].toLong() and 0xFFL) shl (index * 8))
        }
    }

    private fun ByteArray.toHexPrefix(maxBytes: Int = DEFAULT_PREFIX_BYTES): String {
        return take(maxBytes).joinToString(" ") { "%02X".format(it.toInt() and 0xFF) }
    }

    private companion object {
        const val DEFAULT_PREFIX_BYTES = 32
        const val INT_SIZE_BYTES = 4
        const val MAX_AUTHORIZATION_COUNT = 256
        const val MIN_REPLY_BYTES = 48
        const val AUTHORIZATION_COUNT_OFFSET = 44
        const val AUTHORIZATION_LOGICAL_START_OFFSET = 32
        const val AUTHORIZATION_SLOT_SIZE = 16
        const val AUTHORIZATION_TAG_OFFSET = 4
        const val AUTHORIZATION_UNION_TAG_OFFSET = 8
        const val AUTHORIZATION_VALUE_OFFSET = 12
        const val TARGET_MODIFICATION_TIME_MS = 4294967297L
        const val DER_SEQUENCE_PREFIX_0 = 0x30
        const val DER_SEQUENCE_PREFIX_1 = 0x82
        val KNOWN_KEY_PARAMETER_VALUE_UNION_TAGS = (0L..14L).toSet()
        val MODIFICATION_TIME_SIGNATURE_PREFIX = byteArrayOf(
            0x24,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x18,
            0x00,
            0x00,
            0x00,
        )
    }
}
