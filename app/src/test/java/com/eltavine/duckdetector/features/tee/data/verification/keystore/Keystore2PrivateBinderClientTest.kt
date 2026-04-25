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

import android.os.Build
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class Keystore2PrivateBinderClientTest {

    private val client = Keystore2PrivateBinderClient()

    @Test
    fun `request builder keeps alias and interface descriptor`() {
        val request = client.buildGetKeyEntryRequest("duck_alias")

        assertEquals(Keystore2PrivateBinderClient.INTERFACE_DESCRIPTOR, request.interfaceDescriptor)
        assertEquals(Keystore2PrivateBinderClient.TRANSACTION_GET_KEY_ENTRY, request.transactionCode)
        assertEquals("duck_alias", request.alias)
    }

    @Test
    fun `selection parser keeps register timer metadata`() {
        val selection = com.eltavine.duckdetector.features.tee.data.native.TeeRegisterTimerNativeBridge()
            .parseSelection(
                "REGISTER_TIMER_AVAILABLE=1\n" +
                        "TIMER_SOURCE=arm64_cntvct\n" +
                        "AFFINITY=bound_cpu0\n"
            )

        assertTrue(selection.registerTimerAvailable)
        assertEquals("arm64_cntvct", selection.timerSource)
        assertEquals("bound_cpu0", selection.affinityStatus)
        assertNull(selection.fallbackReason)
    }

    @Test
    fun `reply snapshot and failure types keep expected metadata`() {
        val failure = BinderTransactionResult(
            success = false,
            replyFailureReason = "boom",
            throwable = IllegalStateException("boom"),
        )
        val success = BinderTransactionResult(
            success = true,
            replySnapshot = Keystore2ReplySnapshot(
                rawPrefix = "F8 FF FF FF 07 00 00 00",
                exceptionCode = -8,
                secondWord = 7,
                dataSize = 8,
            ),
        )

        assertFalse(failure.success)
        assertNotNull(failure.throwable)
        assertTrue(failure.replyFailureReason!!.contains("boom"))

        assertTrue(success.success)
        val snapshot = success.replySnapshot
        assertNotNull(snapshot)
        snapshot!!
        assertEquals(-8, snapshot.exceptionCode)
        assertEquals(7, snapshot.secondWord)
        assertTrue(snapshot.rawPrefix!!.isNotBlank())
    }

    @Test
    fun `hook result classifier detects java style key not found response`() {
        val snapshot = Keystore2ReplySnapshot(
            rawPrefix = "F8 FF FF FF 07 00 00 00",
            exceptionCode = -8,
            secondWord = 7,
            dataSize = 8,
        )

        val result = classifyKeystore2HookReply(snapshot)

        assertTrue(result.available)
        assertTrue(result.javaHookDetected)
        assertFalse(result.nativeStyleResponse)
        assertEquals(7, result.errorCode)
    }

    @Test
    fun `hook result classifier detects native style response`() {
        val snapshot = Keystore2ReplySnapshot(
            rawPrefix = "F8 FF FF FF FF FF FF FF 00 00 00 00 07 00 00 00",
            exceptionCode = -8,
            secondWord = -1,
            trailingInts = listOf(0, 7),
            dataSize = 16,
        )

        val result = classifyKeystore2HookReply(snapshot)

        assertTrue(result.available)
        assertFalse(result.javaHookDetected)
        assertTrue(result.nativeStyleResponse)
        assertEquals(7, result.errorCode)
    }

    @Test
    fun `positive diff helper is symmetric around threshold`() {
        assertTrue(isPositiveTimingSideChannelDiff(0.2001))
        assertTrue(isPositiveTimingSideChannelDiff(-0.2001))
        assertFalse(isPositiveTimingSideChannelDiff(0.2))
        assertFalse(isPositiveTimingSideChannelDiff(-0.2))
    }

    @Test
    fun `key parameter setter mapping follows AOSP keymint union shape`() {
        assertEquals("setAlgorithm", keyParameterSetterNameForTag(0x10000002))
        assertEquals("setEcCurve", keyParameterSetterNameForTag(0x1000000A))
        assertEquals("setKeyPurpose", keyParameterSetterNameForTag(0x20000001))
        assertEquals("setDigest", keyParameterSetterNameForTag(0x20000005))
        assertEquals("setBoolValue", keyParameterSetterNameForTag(0x700001F7))
        assertEquals("setBlob", keyParameterSetterNameForTag(0x900002C4.toInt()))
    }

    @Test
    fun `parameter type helper preserves primitive reflection types`() {
        assertEquals(Int::class.javaPrimitiveType, keyParameterParameterType(1))
        assertEquals(Long::class.javaPrimitiveType, keyParameterParameterType(1L))
        assertEquals(Boolean::class.javaPrimitiveType, keyParameterParameterType(true))
        assertEquals(ByteArray::class.java, keyParameterParameterType(byteArrayOf(1, 2, 3)))
    }

    @Test
    fun `captured throwable collector de-duplicates same stack`() {
        val collector = CapturedThrowableCollector()
        val failure = IllegalStateException("boom")

        collector.record("warmup.attested[0]", "IllegalStateException: boom", failure)
        collector.record("warmup.attested[1]", "IllegalStateException: boom", failure)

        val records = collector.snapshot()
        assertEquals(1, records.size)
        assertEquals(2, records.single().occurrenceCount)
    }
}
