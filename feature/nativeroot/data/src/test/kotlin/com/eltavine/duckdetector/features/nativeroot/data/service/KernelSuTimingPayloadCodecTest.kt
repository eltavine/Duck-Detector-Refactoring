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

import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingAnalysis
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreAttempt
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreStatus
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingDistance
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingObservation
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingPreflight
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingSimilarity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class KernelSuTimingPayloadCodecTest {
    private val round = KernelSuTimingAnalysis(KernelSuTimingDistance(10000, 0, 10000, 10000),
        KernelSuTimingSimilarity(1.0, 0.0, 1.0, 1.0, 1.0, 10.0, 20.0))

    @Test fun `bounded full summary round trips without raw samples`() {
        val observation = KernelSuTimingObservation(KernelSuTimingCollection.COLLECTED,
            KernelSuTimingPreflight.fromFrequencies(listOf(100uL, 10000uL)), (0..15).toList(),
            (0..15).map { KernelSuTimingCoreAttempt(it, it, KernelSuTimingCoreStatus.MEASURED, List(3) { round }) },
            ULong.MAX_VALUE, true)
        val bytes = KernelSuTimingPayloadCodec.encode(observation)
        assertTrue(bytes.size < 16384)
        assertEquals(observation, KernelSuTimingPayloadCodec.decode(bytes))
    }

    @Test fun `empty statuses and NaN means round trip`() {
        for (state in KernelSuTimingCollection.entries) {
            val observation = KernelSuTimingObservation(collection = state)
            assertEquals(observation, KernelSuTimingPayloadCodec.decode(KernelSuTimingPayloadCodec.encode(observation)))
        }
        val observation = KernelSuTimingObservation(enumeratedCpus = listOf(0), attempts = listOf(
            KernelSuTimingCoreAttempt(0, 0, KernelSuTimingCoreStatus.MEASURED,
                listOf(round.copy(similarity = round.similarity.copy(referenceMean = Double.NaN))))))
        assertEquals(observation, KernelSuTimingPayloadCodec.decode(KernelSuTimingPayloadCodec.encode(observation)))
    }

    @Test fun `truncated oversized unknown version and trailing bytes are rejected`() {
        val bytes = KernelSuTimingPayloadCodec.encode(KernelSuTimingObservation())
        for (bad in listOf(bytes.dropLast(1).toByteArray(), ByteArray(16385), byteArrayOf(0, 0, 0, 2),
            bytes + byteArrayOf(0), bytes.copyOf().apply { this[7] = 127 })) {
            assertThrows(Exception::class.java) { KernelSuTimingPayloadCodec.decode(bad) }
        }
    }
}
