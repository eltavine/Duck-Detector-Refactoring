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

import com.eltavine.duckdetector.core.native.DuckDetectorNativeLibrary
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreStatus
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingProfile
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingSyscallSummary

internal data class KernelSuTimingWindow(
    val status: KernelSuTimingCoreStatus?,
    val actualCpu: Int?,
    val frequency: ULong,
    val cleanup: Boolean,
    val vectors: List<List<ULong>>,
    val allowedCpus: List<Int>,
    val outcomes: List<KernelSuTimingSyscallSummary>,
)

internal class KernelSuTimingNativeBridge {
    fun sample(cpu: Int, preflight: Boolean): KernelSuTimingWindow {
        check(DuckDetectorNativeLibrary.isLoaded) { "Native library unavailable" }
        return parse(nativeSample(cpu, preflight), preflight)
    }

    fun affinity(): List<Int> {
        check(DuckDetectorNativeLibrary.isLoaded) { "Native library unavailable" }
        val raw = nativeAffinity()
        require(raw.size in 1..1025 && raw[0] in 0..4095)
        check(raw[0] == 0L) { "sched_getaffinity errno=${raw[0]}" }
        return raw.drop(1).map { require(it in 0L..1023L); it.toInt() }
            .also { require(it == it.distinct().sorted()) }
    }

    internal fun parse(raw: LongArray, preflight: Boolean): KernelSuTimingWindow {
        require(raw.size in 8..62000)
        var offset = 0
        fun next(): Long { require(offset < raw.size); return raw[offset++] }
        fun count(maximum: Int) = next().also { require(it in 0..maximum.toLong()) }.toInt()
        require(next() == 2L)
        val status = count(6)
        val actual = next().also { require(it in -1L..1023L) }.toInt().takeIf { it >= 0 }
        val frequency = next().toULong()
        val cleanup = count(1) == 1
        val allowed = List(count(1024)) { count(1023) }.also { require(it == it.distinct().sorted()) }
        val vectorCount = count(6)
        require(vectorCount == 0 || vectorCount == if (preflight) 1 else 6)
        val outcomes = List(vectorCount) {
            val entries = List(count(8)) { next() to count(10000) }
            require(entries.map { it.first }.distinct().size == entries.size)
            KernelSuTimingSyscallSummary(entries.toMap(), count(10000), count(10000), count(30000), count(3), count(10000))
        }
        val ticks = count(60000)
        val expected = (if (preflight) 1 else 6) * KernelSuTimingProfile.SAMPLE_COUNT
        require(ticks == if (status == 0) expected else 0)
        require(status != 0 || (frequency != 0uL && actual != null && cleanup && vectorCount > 0))
        require(raw.size - offset == ticks)
        val vectors = raw.drop(offset).map { it.toULong() }.chunked(KernelSuTimingProfile.SAMPLE_COUNT)
        return KernelSuTimingWindow(if (status == 6) null else KernelSuTimingCoreStatus.entries[status],
            actual, frequency, cleanup, vectors, allowed, outcomes)
    }

    private external fun nativeSample(cpu: Int, preflight: Boolean): LongArray
    private external fun nativeAffinity(): LongArray
}
