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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GenerateKeyReplyParcelParserTest {

    private val parser = GenerateKeyReplyParcelParser()

    @Test
    fun `generate mode fixture keeps hit shape metadata`() {
        val result = parser.parse(rawReply = hexToBytes(GENERATE_MODE_REPLY_HEX))

        assertTrue(result.parseSucceeded)
        assertEquals(13, result.authorizationCount)
        assertEquals(256L, result.lastAuthorizationSecLevel)
        assertEquals(1L, result.lastAuthorizationTag)
        assertEquals(32L, result.lastAuthorizationUnionTag)
        assertTrue(result.lastAuthorizationHasUnknownUnionTag)
        assertEquals(4_294_967_297L, result.modificationTimeMs)
        assertTrue(result.matched)
    }

    @Test
    fun `project docs parcel fingerprint enabled generate mode fixture matches stable fingerprint tuple`() {
        val result = parser.parse(rawReply = hexToBytes(PARCEL_FINGERPRINT_ENABLED_GENERATE_MODE_REPLY_HEX))

        assertTrue(result.parseSucceeded)
        assertEquals(13, result.authorizationCount)
        assertEquals(256L, result.lastAuthorizationSecLevel)
        assertEquals(1L, result.lastAuthorizationTag)
        assertEquals(32L, result.lastAuthorizationUnionTag)
        assertTrue(result.lastAuthorizationHasUnknownUnionTag)
        assertEquals(4_294_967_297L, result.modificationTimeMs)
        assertTrue(result.matched)
    }

    @Test
    fun `stable fingerprint does not depend on authorization count`() {
        val result = parser.parse(rawReply = variableCountGenerateModeReply())

        assertTrue(result.parseSucceeded)
        assertEquals(2, result.authorizationCount)
        assertEquals(256L, result.lastAuthorizationSecLevel)
        assertEquals(1L, result.lastAuthorizationTag)
        assertEquals(32L, result.lastAuthorizationUnionTag)
        assertTrue(result.lastAuthorizationHasUnknownUnionTag)
        assertEquals(4_294_967_297L, result.modificationTimeMs)
        assertTrue(result.matched)
    }

    @Test
    fun `stable fingerprint accepts tee security level in last authorization`() {
        val result = parser.parse(rawReply = variableCountGenerateModeReply(lastSecLevel = 4))

        assertTrue(result.parseSucceeded)
        assertEquals(4L, result.lastAuthorizationSecLevel)
        assertEquals(1L, result.lastAuthorizationTag)
        assertEquals(32L, result.lastAuthorizationUnionTag)
        assertEquals(4_294_967_297L, result.modificationTimeMs)
        assertTrue(result.matched)
    }

    @Test
    fun `normal fixture keeps non hit shape metadata`() {
        val result = parser.parse(rawReply = hexToBytes(NORMAL_REPLY_HEX))

        assertTrue(result.parseSucceeded)
        assertEquals(12, result.authorizationCount)
        assertEquals(20L, result.lastAuthorizationSecLevel)
        assertEquals(1_879_048_695L, result.lastAuthorizationTag)
        assertEquals(1L, result.lastAuthorizationUnionTag)
        assertFalse(result.lastAuthorizationHasUnknownUnionTag)
        assertEquals(4_563_403_454L, result.modificationTimeMs)
        assertFalse(result.matched)
    }

    @Test
    fun `leaf certificate fixture keeps non hit shape metadata`() {
        val result = parser.parse(rawReply = hexToBytes(LEAF_CERTIFICATE_REPLY_HEX))

        assertTrue(result.parseSucceeded)
        assertEquals(12, result.authorizationCount)
        assertEquals(20L, result.lastAuthorizationSecLevel)
        assertEquals(1_879_048_695L, result.lastAuthorizationTag)
        assertEquals(1L, result.lastAuthorizationUnionTag)
        assertFalse(result.lastAuthorizationHasUnknownUnionTag)
        assertEquals(4_563_403_454L, result.modificationTimeMs)
        assertFalse(result.matched)
    }

    @Test
    fun `fingerprint does not match when modification time differs`() {
        val result = parser.parse(rawReply = variableCountGenerateModeReply(modificationTimeMs = 4_294_967_298L))

        assertTrue(result.parseSucceeded)
        assertEquals(256L, result.lastAuthorizationSecLevel)
        assertEquals(32L, result.lastAuthorizationUnionTag)
        assertFalse(result.matched)
    }

    @Test
    fun `fingerprint does not match when last authorization security level differs`() {
        val result = parser.parse(rawReply = variableCountGenerateModeReply(lastSecLevel = 20))

        assertTrue(result.parseSucceeded)
        assertEquals(20L, result.lastAuthorizationSecLevel)
        assertEquals(32L, result.lastAuthorizationUnionTag)
        assertEquals(4_294_967_297L, result.modificationTimeMs)
        assertFalse(result.matched)
    }

    @Test
    fun `fingerprint does not match when last authorization tag differs`() {
        val result = parser.parse(rawReply = variableCountGenerateModeReply(lastTag = 0x00000020))

        assertTrue(result.parseSucceeded)
        assertEquals(256L, result.lastAuthorizationSecLevel)
        assertEquals(32L, result.lastAuthorizationTag)
        assertEquals(32L, result.lastAuthorizationUnionTag)
        assertEquals(4_294_967_297L, result.modificationTimeMs)
        assertFalse(result.matched)
    }

    @Test
    fun `fingerprint does not match when unknown union tag is not on last authorization`() {
        val result = parser.parse(
            rawReply = variableCountGenerateModeReply(
                firstUnionTag = 32,
                lastUnionTag = 1,
            ),
        )

        assertTrue(result.parseSucceeded)
        assertEquals(1L, result.lastAuthorizationUnionTag)
        assertEquals(4_294_967_297L, result.modificationTimeMs)
        assertFalse(result.matched)
    }

    @Test
    fun `fingerprint does not parse failed reply as matched`() {
        val bytes = variableCountGenerateModeReply()
        bytes[0] = 1

        val result = parser.parse(rawReply = bytes)

        assertFalse(result.parseSucceeded)
        assertFalse(result.matched)
    }

    private fun hexToBytes(rawHex: String): ByteArray {
        val compact = rawHex.replace(Regex("[^0-9A-Fa-f]"), "")
        require(compact.length % 2 == 0) { "hex fixture must have even length" }
        return ByteArray(compact.length / 2) { index ->
            compact.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private fun variableCountGenerateModeReply(
        firstUnionTag: Int = 1,
        lastSecLevel: Int = 256,
        lastTag: Int = 0x00000001,
        lastUnionTag: Int = 32,
        modificationTimeMs: Long = 4_294_967_297L,
    ): ByteArray {
        return buildList {
            addIntLe(0)
            addKeyDescriptorHeader(totalPayloadBytes = 0)
            addIntLe(1)
            addIntLe(2)
            addAuthorization(secLevel = 1, tag = 0x00000020, unionTag = firstUnionTag, value = 1)
            addAuthorization(secLevel = lastSecLevel, tag = lastTag, unionTag = lastUnionTag, value = 1)
            addIntLe(1)
            addIntLe(1)
            add(0xAA.toByte())
            padToParcelWord()
            addIntLe(1)
            addIntLe(1)
            add(0xBB.toByte())
            padToParcelWord()
            addLongLe(modificationTimeMs)
        }.toByteArray()
    }

    private fun MutableList<Byte>.addKeyDescriptorHeader(totalPayloadBytes: Int) {
        addIntLe(totalPayloadBytes)
        addIntLe(1)
        addIntLe(24)
        addIntLe(4)
        addLongLe(0x1122334455667788L)
        addLongLe(-1L)
        addIntLe(1)
    }

    private fun MutableList<Byte>.addAuthorization(
        secLevel: Int,
        tag: Int,
        unionTag: Int,
        value: Int,
    ) {
        addIntLe(secLevel)
        addIntLe(tag)
        addIntLe(unionTag)
        if (unionTag in 1..11) {
            addIntLe(value)
        }
    }

    private fun MutableList<Byte>.addIntLe(value: Int) {
        add((value and 0xFF).toByte())
        add(((value ushr 8) and 0xFF).toByte())
        add(((value ushr 16) and 0xFF).toByte())
        add(((value ushr 24) and 0xFF).toByte())
    }

    private fun MutableList<Byte>.addLongLe(value: Long) {
        repeat(Long.SIZE_BYTES) { index ->
            add(((value ushr (index * Byte.SIZE_BITS)) and 0xFF).toByte())
        }
    }

    private fun MutableList<Byte>.padToParcelWord() {
        while (size % Int.SIZE_BYTES != 0) {
            add(0)
        }
    }

    private companion object {
        private val GENERATE_MODE_REPLY_HEX = """
            00 00 00 00 01 00 00 00 AC 0F 00 00 01 00 00 00
            18 00 00 00 04 00 00 00 17 5C BC 3F B4 F3 50 66
            FF FF FF FF FF FF FF FF 01 00 00 00 0D 00 00 00
            01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
            14 00 00 00 02 00 00 10 01 00 00 00 01 00 00 00
            03 00 00 00 01 00 00 00 20 00 00 00 01 00 00 00
            01 00 00 00 14 00 00 00 0A 00 00 10 01 00 00 00
            05 00 00 00 01 00 00 00 01 00 00 00 20 00 00 00
            01 00 00 00 01 00 00 00 14 00 00 00 01 00 00 20
            01 00 00 00 07 00 00 00 02 00 00 00 01 00 00 00
            20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
            05 00 00 20 01 00 00 00 04 00 00 00 04 00 00 00
            01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
            14 00 00 00 03 00 00 30 01 00 00 00 0B 00 00 00
            00 01 00 00 01 00 00 00 20 00 00 00 01 00 00 00
            01 00 00 00 14 00 00 00 F7 01 00 70 01 00 00 00
            0A 00 00 00 01 00 00 00 01 00 00 00 20 00 00 00
            01 00 00 00 01 00 00 00 14 00 00 00 BE 02 00 10
            01 00 00 00 06 00 00 00 00 00 00 00 01 00 00 00
            20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
            C1 02 00 30 01 00 00 00 0B 00 00 00 00 71 02 00
            01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
            14 00 00 00 C2 02 00 30 01 00 00 00 0B 00 00 00
            69 17 03 00 01 00 00 00 20 00 00 00 01 00 00 00
            01 00 00 00 14 00 00 00 CE 02 00 30 01 00 00 00
            0B 00 00 00 05 25 35 01 01 00 00 00 20 00 00 00
            01 00 00 00 01 00 00 00 14 00 00 00 CF 02 00 30
            01 00 00 00 0B 00 00 00 05 25 35 01 01 00 00 00
            24 00 00 00 00 00 00 00 01 00 00 00 18 00 00 00
            BD 02 00 60 01 00 00 00 0D 00 00 00 FF 7D 43 77
            9D 01 00 00 01 00 00 00 20 00 00 00 00 00 00 00
            01 00 00 00 14 00 00 00 F5 01 00 30 01 00 00 00
            0B 00 00 00 00 00 00 00 A5 02 00 00 30 82 02 A1
        """.trimIndent()

        private val PARCEL_FINGERPRINT_ENABLED_GENERATE_MODE_REPLY_HEX = """
            00 00 00 00 01 00 00 00 30 10 00 00 01 00 00 00
            18 00 00 00 04 00 00 00 D6 AD B5 F4 A6 D8 D0 FD
            FF FF FF FF FF FF FF FF 01 00 00 00 0D 00 00 00
            01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
            14 00 00 00 02 00 00 10 01 00 00 00 01 00 00 00
            03 00 00 00 01 00 00 00 20 00 00 00 01 00 00 00
            01 00 00 00 14 00 00 00 0A 00 00 10 01 00 00 00
            05 00 00 00 01 00 00 00 01 00 00 00 20 00 00 00
            01 00 00 00 01 00 00 00 14 00 00 00 01 00 00 20
            01 00 00 00 07 00 00 00 02 00 00 00 01 00 00 00
            20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
            05 00 00 20 01 00 00 00 04 00 00 00 04 00 00 00
            01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
            14 00 00 00 03 00 00 30 01 00 00 00 0B 00 00 00
            00 01 00 00 01 00 00 00 20 00 00 00 01 00 00 00
            01 00 00 00 14 00 00 00 F7 01 00 70 01 00 00 00
            0A 00 00 00 01 00 00 00 01 00 00 00 20 00 00 00
            01 00 00 00 01 00 00 00 14 00 00 00 BE 02 00 10
            01 00 00 00 06 00 00 00 00 00 00 00 01 00 00 00
            20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
            C1 02 00 30 01 00 00 00 0B 00 00 00 00 71 02 00
            01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
            14 00 00 00 C2 02 00 30 01 00 00 00 0B 00 00 00
            6D 17 03 00 01 00 00 00 20 00 00 00 01 00 00 00
            01 00 00 00 14 00 00 00 CE 02 00 30 01 00 00 00
            0B 00 00 00 99 26 35 01 01 00 00 00 20 00 00 00
            01 00 00 00 01 00 00 00 14 00 00 00 CF 02 00 30
            01 00 00 00 0B 00 00 00 99 26 35 01 01 00 00 00
            24 00 00 00 64 00 00 00 01 00 00 00 18 00 00 00
            BD 02 00 60 01 00 00 00 0D 00 00 00 07 2E 17 43
            9E 01 00 00 01 00 00 00 20 00 00 00 64 00 00 00
            01 00 00 00 14 00 00 00 F5 01 00 30 01 00 00 00
            0B 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00
            AA 00 00 00 01 00 00 00 01 00 00 00 BB 00 00 00
            01 00 00 00 01 00 00 00
        """.trimIndent()

        private val NORMAL_REPLY_HEX = """
            00 00 00 00 01 00 00 00 84 0F 00 00 01 00 00 00
            18 00 00 00 04 00 00 00 F2 BA 9D E8 1B 29 76 80
            FF FF FF FF FF FF FF FF 01 00 00 00 0C 00 00 00
            01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
            14 00 00 00 01 00 00 20 01 00 00 00 07 00 00 00
            02 00 00 00 01 00 00 00 20 00 00 00 01 00 00 00
            01 00 00 00 14 00 00 00 02 00 00 10 01 00 00 00
            01 00 00 00 03 00 00 00 01 00 00 00 20 00 00 00
            01 00 00 00 01 00 00 00 14 00 00 00 05 00 00 20
            01 00 00 00 04 00 00 00 04 00 00 00 01 00 00 00
            20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
            0A 00 00 10 01 00 00 00 05 00 00 00 01 00 00 00
            01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
            14 00 00 00 F7 01 00 70 01 00 00 00 0A 00 00 00
            01 00 00 00 01 00 00 00 20 00 00 00 01 00 00 00
            01 00 00 00 14 00 00 00 BE 02 00 10 01 00 00 00
            06 00 00 00 00 00 00 00 01 00 00 00 20 00 00 00
            01 00 00 00 01 00 00 00 14 00 00 00 C1 02 00 30
            01 00 00 00 0B 00 00 00 00 71 02 00 01 00 00 00
            20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
            C2 02 00 30 01 00 00 00 0B 00 00 00 69 17 03 00
            01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
            14 00 00 00 CE 02 00 30 01 00 00 00 0B 00 00 00
            05 25 35 01 01 00 00 00 20 00 00 00 01 00 00 00
            01 00 00 00 14 00 00 00 CF 02 00 30 01 00 00 00
            0B 00 00 00 05 25 35 01 01 00 00 00 24 00 00 00
            64 00 00 00 01 00 00 00 18 00 00 00 BD 02 00 60
            01 00 00 00 0D 00 00 00 CB 85 57 77 9D 01 00 00
            01 00 00 00 20 00 00 00 00 00 00 00 01 00 00 00
            14 00 00 00 F5 01 00 30 01 00 00 00 0B 00 00 00
            00 00 00 00 A1 02 00 00 30 82 02 9D
        """.trimIndent()

        private val LEAF_CERTIFICATE_REPLY_HEX = """
            00 00 00 00 01 00 00 00 84 0F 00 00 01 00 00 00
            18 00 00 00 04 00 00 00 BC 84 B4 88 D4 43 F5 FE
            FF FF FF FF FF FF FF FF 01 00 00 00 0C 00 00 00
            01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
            14 00 00 00 01 00 00 20 01 00 00 00 07 00 00 00
            02 00 00 00 01 00 00 00 20 00 00 00 01 00 00 00
            01 00 00 00 14 00 00 00 02 00 00 10 01 00 00 00
            01 00 00 00 03 00 00 00 01 00 00 00 20 00 00 00
            01 00 00 00 01 00 00 00 14 00 00 00 05 00 00 20
            01 00 00 00 04 00 00 00 04 00 00 00 01 00 00 00
            20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
            0A 00 00 10 01 00 00 00 05 00 00 00 01 00 00 00
            01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
            14 00 00 00 F7 01 00 70 01 00 00 00 0A 00 00 00
            01 00 00 00 01 00 00 00 20 00 00 00 01 00 00 00
            01 00 00 00 14 00 00 00 BE 02 00 10 01 00 00 00
            06 00 00 00 00 00 00 00 01 00 00 00 20 00 00 00
            01 00 00 00 01 00 00 00 14 00 00 00 C1 02 00 30
            01 00 00 00 0B 00 00 00 00 71 02 00 01 00 00 00
            20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
            C2 02 00 30 01 00 00 00 0B 00 00 00 69 17 03 00
            01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
            14 00 00 00 CE 02 00 30 01 00 00 00 0B 00 00 00
            05 25 35 01 01 00 00 00 20 00 00 00 01 00 00 00
            01 00 00 00 14 00 00 00 CF 02 00 30 01 00 00 00
            0B 00 00 00 05 25 35 01 01 00 00 00 24 00 00 00
            64 00 00 00 01 00 00 00 18 00 00 00 BD 02 00 60
            01 00 00 00 0D 00 00 00 5E FA 46 77 9D 01 00 00
            01 00 00 00 20 00 00 00 00 00 00 00 01 00 00 00
            14 00 00 00 F5 01 00 30 01 00 00 00 0B 00 00 00
            00 00 00 00 A3 02 00 00 30 82 02 9F
        """.trimIndent()
    }
}
