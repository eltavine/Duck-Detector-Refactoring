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
import org.junit.Assert.assertNull
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
        assertNull(result.modificationTimeMs)
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
        assertNull(result.modificationTimeMs)
    }

    private fun hexToBytes(rawHex: String): ByteArray {
        val compact = rawHex.replace(Regex("[^0-9A-Fa-f]"), "")
        require(compact.length % 2 == 0) { "hex fixture must have even length" }
        return ByteArray(compact.length / 2) { index ->
            compact.substring(index * 2, index * 2 + 2).toInt(16).toByte()
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
