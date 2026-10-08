/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.features.nativeroot.data.service

import com.eltavine.duckdetector.features.nativeroot.data.native.SrcuTimingNativeBridge
import com.eltavine.duckdetector.features.nativeroot.domain.ROUND_COUNT
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuCloseSample
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuCloseStage
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingObservation
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingRound
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingWindow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SrcuTimingPayloadCodecTest {
    private val window = SrcuTimingWindow(100, 900, false,
        listOf(SrcuCloseSample(110, 160, SrcuCloseStage.OK)))
    @Test fun `nested timing windows preserve timestamps and escaped failure details`() {
        val observation = SrcuTimingObservation(SrcuTimingCollection.COLLECTED,
            listOf(SrcuTimingRound(window, window, window)), "6.12.81", "backslash\\tab\tline\n", true)
        assertEquals(observation, SrcuTimingPayloadCodec.decode(SrcuTimingPayloadCodec.encode(observation)))
    }
    @Test fun `failed native stage and errno survive remote transport`() {
        val failed = window.copy(samples = listOf(SrcuCloseSample(0, 0, SrcuCloseStage.WATCH_FAILED, 13)))
        val observation = SrcuTimingObservation(SrcuTimingCollection.NATIVE_FAILED, failedWindow = failed)
        assertEquals(observation, SrcuTimingPayloadCodec.decode(SrcuTimingPayloadCodec.encode(observation)))
    }
    @Test fun `missing duplicate malformed and mismatched samples are rejected`() {
        val valid = "VERSION=1\nBEGIN=100\nEND=200\nSATURATED=0\nCOUNT=1\nSAMPLE=110\t160\t0\t0\n"
        val parser = SrcuTimingNativeBridge()
        assertEquals(window.copy(endNanos = 200), parser.parse(valid))
        for (bad in listOf("", valid.replace("COUNT=1", "COUNT=2"),
            valid + "BEGIN=500\n", valid.replace("\t0\t0", "\t99\t0"),
            valid.replace("SATURATED=0", "SATURATED=unknown"))) {
            assertThrows(Exception::class.java) { parser.parse(bad) }
        }
    }
    @Test fun `maximum bounded run fits remote transport without dropping samples`() {
        val full = window.copy(beginNanos = Long.MAX_VALUE - 1000, endNanos = Long.MAX_VALUE,
            samples = List(128) { SrcuCloseSample(Long.MAX_VALUE - 999, Long.MAX_VALUE, SrcuCloseStage.OK) })
        val observation = SrcuTimingObservation(SrcuTimingCollection.COLLECTED,
            List(ROUND_COUNT) { SrcuTimingRound(full, full, full) }, failedWindow = full)
        val payload = SrcuTimingPayloadCodec.encode(observation)
        assertTrue(payload.length * 2 < 900000)
        assertEquals(observation, SrcuTimingPayloadCodec.decode(payload))
    }
    @Test fun `oversized remote payload is rejected before it is parsed`() {
        assertThrows(IllegalArgumentException::class.java) { SrcuTimingPayloadCodec.decode("x".repeat(SrcuTimingPayloadCodec.MAX_LENGTH + 1)) }
    }
}
