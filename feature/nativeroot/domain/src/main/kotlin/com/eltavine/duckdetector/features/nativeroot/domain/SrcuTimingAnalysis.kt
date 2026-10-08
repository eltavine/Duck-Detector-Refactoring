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

package com.eltavine.duckdetector.features.nativeroot.domain

import kotlin.math.abs
import kotlin.math.ceil

/** Experimental, scale-relative criterion; it does not identify a reader or certify a kernel. */
fun analyzeSrcuTiming(observation: SrcuTimingObservation): SrcuTimingAnalysis {
    if (observation.collection != SrcuTimingCollection.COLLECTED || !observation.cleanupCompleted) {
        return SrcuTimingAnalysis(SrcuTimingVerdict.NOT_EVALUATED)
    }
    val rounds = observation.rounds
    if (rounds.size != ROUND_COUNT || rounds.any {
        listOf(it.idle, it.stimulated, it.sequential).any { window ->
            !window.complete || window.usableSamples.size < MIN_SAMPLES
        }
    }) return SrcuTimingAnalysis(SrcuTimingVerdict.INCONCLUSIVE)

    fun durations(window: SrcuTimingWindow) = window.usableSamples.map { it.durationNanos }
    val idle = rounds.flatMap { durations(it.idle) }
    val stimulated = rounds.flatMap { durations(it.stimulated) }
    val sequential = rounds.flatMap { durations(it.sequential) }
    val idleMedian = percentile(idle, 0.5)
    val sequentialMedian = percentile(sequential, 0.5)
    val noise = maxOf(mad(idle), mad(sequential), idleMedian / 10, sequentialMedian / 10, 1L)
    val idleP95 = percentile(idle, 0.95)
    val stimulatedP95 = percentile(stimulated, 0.95)
    val sequentialP95 = percentile(sequential, 0.95)
    val delayed = rounds.map { round ->
        val baseline = maxOf(percentile(durations(round.idle), 0.95),
            percentile(durations(round.sequential), 0.95))
        percentile(durations(round.stimulated), 0.95).toDouble() - baseline > noise.toDouble() * 6
    }
    // One reader blocks one close per stimulated window, and a p95 stops seeing a single close once a
    // window holds 20 samples. A stimulated close longer than both controls cannot then read as absence.
    val outlier = rounds.any { round ->
        durations(round.stimulated).max().toDouble() -
            maxOf(durations(round.idle).max(), durations(round.sequential).max()) > noise.toDouble() * 6
    }
    // An elevated sequential control or unstable idle distribution defeats attribution to overlap.
    val noisy = abs(sequentialMedian.toDouble() - idleMedian) > noise.toDouble() * 6 ||
        idleP95.toDouble() - idleMedian > maxOf(idleMedian.toDouble(), noise.toDouble() * 12)
    val replicated = delayed.count { it } >= 10 &&
        delayed.chunked(4).all { block -> block.count { it } >= 3 }
    val verdict = when {
        noisy -> SrcuTimingVerdict.INCONCLUSIVE
        replicated && stimulatedP95.toDouble() - maxOf(idleP95, sequentialP95) > noise.toDouble() * 6 ->
            SrcuTimingVerdict.REPEATABLE_DELAY
        delayed.any { it } || outlier -> SrcuTimingVerdict.INCONCLUSIVE
        else -> SrcuTimingVerdict.NOT_OBSERVED
    }
    return SrcuTimingAnalysis(verdict, rounds.size, delayed.count { it }, idleP95,
        stimulatedP95, sequentialP95)
}

internal fun percentile(values: List<Long>, quantile: Double): Long =
    values.sorted()[(ceil(values.size * quantile).toInt() - 1).coerceAtLeast(0)]

private fun mad(values: List<Long>): Long {
    val median = percentile(values, 0.5)
    return percentile(values.map { abs(it - median) }, 0.5)
}

const val ROUND_COUNT = 12
private const val MIN_SAMPLES = 8
