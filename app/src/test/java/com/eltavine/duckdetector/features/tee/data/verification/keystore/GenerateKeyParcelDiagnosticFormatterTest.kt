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

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GenerateKeyParcelDiagnosticFormatterTest {

    private val parser = GenerateKeyReplyParcelParser()

    @Test
    fun `formatter includes request reply raw hex and stable fingerprint tuple`() {
        val rawReply = generateModeReply()
        val parsed = parser.parse(rawReply = rawReply)
        val diagnostic = GenerateKeyParcelDiagnosticFormatter.format(
            rawRequest = generateKeyRequest(),
            rawReply = rawReply,
            parseResult = parsed,
            captureDetail = "captured for test",
        )

        assertTrue(diagnostic.contains("GENERATEKEY transaction atomic structure dump"))
        assertTrue(diagnostic.contains("interface descriptor: android.system.keystore2.IKeystoreSecurityLevel"))
        assertTrue(diagnostic.contains("Count: 2"))
        assertTrue(diagnostic.contains("SecLevel: 256"))
        assertTrue(diagnostic.contains("Unknown UnionTag: 32"))
        assertTrue(diagnostic.contains("modificationTimeMs: 4294967297"))
        assertTrue(diagnostic.contains("matched: true"))
        assertTrue(diagnostic.contains("--- [Reply Raw Hex] ---"))
        assertTrue(diagnostic.contains("AA 00 00 00"))
        assertFalse(diagnostic.contains("authorizationCount == 13"))
    }

    @Test
    fun `formatter keeps failure replies as diagnostic detail only`() {
        val rawReply = generateModeReply().also { it[0] = 1 }
        val parsed = parser.parse(rawReply = rawReply)
        val diagnostic = GenerateKeyParcelDiagnosticFormatter.format(
            rawRequest = null,
            rawReply = rawReply,
            parseResult = parsed,
            captureDetail = "captured failed reply",
        )

        assertTrue(diagnostic.contains("exception header: 1 (ERROR)"))
        assertTrue(diagnostic.contains("matched: false"))
        assertFalse(diagnostic.contains("KeyMetadata return value parse"))
    }

    private fun generateKeyRequest(): ByteArray {
        return buildList {
            addIntLe(0)
            addParcelString("android.system.keystore2.IKeystoreSecurityLevel")
        }.toByteArray()
    }

    private fun generateModeReply(
        firstUnionTag: Int = 1,
        lastSecLevel: Int = 256,
        lastUnionTag: Int = 32,
        modificationTimeMs: Long = 4_294_967_297L,
    ): ByteArray {
        return buildList {
            addIntLe(0)
            addKeyDescriptorHeader(totalPayloadBytes = 0)
            addIntLe(1)
            addIntLe(2)
            addAuthorization(secLevel = 1, tag = 0x00000020, unionTag = firstUnionTag, value = 1)
            addAuthorization(secLevel = lastSecLevel, tag = 0x00000001, unionTag = lastUnionTag, value = 1)
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

    private fun MutableList<Byte>.addParcelString(value: String) {
        addIntLe(value.length)
        value.forEach { char ->
            add((char.code and 0xFF).toByte())
            add(((char.code ushr Byte.SIZE_BITS) and 0xFF).toByte())
        }
        add(0)
        add(0)
        padToParcelWord()
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
}
