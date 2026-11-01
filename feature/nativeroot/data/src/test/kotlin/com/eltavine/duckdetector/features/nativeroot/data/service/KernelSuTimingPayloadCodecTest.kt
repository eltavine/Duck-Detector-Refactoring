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

import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingClassifier
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreAttempt
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreStatus
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCpuSnapshot
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingObservation
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingPreflight
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingSyscallSummary
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingWindowEvidence
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class KernelSuTimingPayloadCodecTest {
    private val round = KernelSuTimingClassifier.summarize(listOf(10uL, 20uL, 10uL, 10uL, 10uL, 10uL)
        .map { tick -> List(10000) { tick } })
    private val cpus = KernelSuTimingCpuSnapshot((0..1023).toList(), (0..1023).toList(), (0..1023).toList())
    private val outcome = KernelSuTimingSyscallSummary((0L..7L).associateWith { 1000 },
        otherOutcomes = 2000, retriedSamples = 10000, totalRetries = 30000, maximumRetries = 3, retryLimitSamples = 10000)
    private fun observation() = KernelSuTimingObservation(collection = KernelSuTimingCollection.PARTIAL,
        initialCpus = cpus, finalCpus = cpus, cleanupCompleted = true,
        attempts = (0..15).map { cpu -> KernelSuTimingCoreAttempt(cpu, cpu, KernelSuTimingCoreStatus.OUTCOME_CONTAMINATED,
            List(3) { round }, KernelSuTimingPreflight.fromFrequencies(listOf(1000uL, 10000uL)),
            List(4) { index -> KernelSuTimingWindowEvidence(cpus, cpus, cpus.allowed.orEmpty(),
                List(if (index == 0) 1 else 6) { outcome }, ULong.MAX_VALUE) }) })

    @Test fun `bounded maximum summary preserves snapshots outcomes retries and retained support`() {
        val observation = observation()
        val bytes = KernelSuTimingPayloadCodec.encode(observation)
        assertTrue(bytes.size < 196608)
        assertEquals(observation, KernelSuTimingPayloadCodec.decode(bytes))
        assertEquals(observation.verdict, KernelSuTimingPayloadCodec.decode(bytes).verdict)
    }

    @Test fun `empty statuses unknown CPU state and invalid classifier metrics round trip`() {
        for (state in KernelSuTimingCollection.entries) {
            val value = KernelSuTimingObservation(collection = state)
            assertEquals(value, KernelSuTimingPayloadCodec.decode(KernelSuTimingPayloadCodec.encode(value)))
        }
        val invalid = round.copy(similarity = round.similarity.copy(referenceMean = Double.NaN,
            referenceSimilarity = Double.NaN))
        val value = observation().let { it.copy(attempts = listOf(it.attempts.first().copy(rounds = listOf(invalid)))) }
        assertEquals(value, KernelSuTimingPayloadCodec.decode(KernelSuTimingPayloadCodec.encode(value)))
    }

    @Test fun `truncated oversized old version and trailing bytes are rejected`() {
        val bytes = KernelSuTimingPayloadCodec.encode(KernelSuTimingObservation())
        for (bad in listOf(bytes.dropLast(1).toByteArray(), ByteArray(196609), byteArrayOf(0, 0, 0, 1),
            bytes + byteArrayOf(0), bytes.copyOf().apply { this[7] = 127 })) {
            assertThrows(Exception::class.java) { KernelSuTimingPayloadCodec.decode(bad) }
        }
    }
}
