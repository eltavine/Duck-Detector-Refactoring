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

package com.eltavine.duckdetector.features.nativeroot.data.native

import com.eltavine.duckdetector.features.nativeroot.domain.InitRcTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.InitRcTimingVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class InitRcTimingNativeBridgeTest {
    private val bridge = InitRcTimingNativeBridge()

    @Test
    fun `complete payload retains typed status and raw timing samples`() {
        val parsed = bridge.parse(payload())
        assertEquals(InitRcTimingCollection.COLLECTED, parsed.collection)
        assertEquals(32, parsed.rounds.size)
        assertEquals(128_000L, parsed.rounds.first().normalControlNanos)
        assertEquals(50.0, parsed.analysis.medianContrastNanos, 0.001)
    }

    @Test
    fun `failed and unsupported payloads never become zero-valued clean measurements`() {
        for (stage in 1..9) {
            val parsed = bridge.parse(payload(stage = stage, count = 0, cpu = -1, cleaned = 0, error = 13))
            assertEquals(stage, parsed.collection.wireCode)
            assertEquals(13, parsed.errorNumber)
            assertEquals(InitRcTimingVerdict.NOT_EVALUATED, parsed.analysis.verdict)
        }
    }

    @Test
    fun `partial samples and primary errno survive collection failure`() {
        val parsed = bridge.parse(payload(stage = 7, count = 2, error = 13))
        assertEquals(2, parsed.rounds.size)
        assertEquals(InitRcTimingCollection.SYSCALL_FAILED, parsed.collection)
        assertEquals(13, parsed.errorNumber)
        assertEquals(InitRcTimingVerdict.NOT_EVALUATED, parsed.analysis.verdict)
    }

    @Test
    fun `contradictory missing duplicate and out of range payloads are rejected`() {
        val valid = payload()
        for (corrupt in listOf(
            "", valid + "STAGE=0\n", valid.replace("VERSION=1", "VERSION=2"),
            valid.replace("STAGE=0", "STAGE=99"), valid.replace("COUNT=32", "COUNT=31"),
            payload(count = 31), payload(cpu = -1), payload(cleaned = 0), payload(error = 1),
            valid.replace("CLEANUP_ERROR=0", "CLEANUP_ERROR=5"),
            valid.replace("ITERATIONS=128", "ITERATIONS=0"),
            valid.replace("ERROR=0\n", "ERROR=-1\n"), valid.replace("CPU=2\n", ""),
            valid.replaceFirst("128000", "0"), valid.replaceFirst("128000", "9223372036854775807"),
            valid + "ROUND=1\t1\t1\t1\n", valid + "bad-field\n", "X".repeat(16_385),
        )) assertThrows(IllegalArgumentException::class.java) { bridge.parse(corrupt) }
    }

    @Test
    fun `payload cannot claim completion with a full second of retained batches`() {
        val invalid = payload().replace("128000\t133120\t138240\t149760", "7812500\t7812500\t7812500\t7812500")
        assertThrows(IllegalArgumentException::class.java) { bridge.parse(invalid) }
    }

    private fun payload(stage: Int = 0, count: Int = 32, cpu: Int = 2, cleaned: Int = 1, error: Int = 0) =
        "VERSION=1\nSTAGE=$stage\nERROR=$error\nCLEANUP_ERROR=0\nCLEANUP=$cleaned\nCPU=$cpu\n" +
            "ITERATIONS=128\nCOUNT=$count\n" + "ROUND=128000\t133120\t138240\t149760\n".repeat(count)
}
