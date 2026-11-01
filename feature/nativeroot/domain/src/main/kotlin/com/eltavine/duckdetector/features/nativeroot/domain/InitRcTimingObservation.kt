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

enum class InitRcTimingCollection(val wireCode: Int) {
    NOT_RUN(-1), COLLECTED(0), UNSUPPORTED_ABI(1), FILE_FAILED(2), THREAD_FAILED(3),
    NAME_FAILED(4), AFFINITY_FAILED(5), CLOCK_FAILED(6), SYSCALL_FAILED(7), TIMED_OUT(8),
    CLEANUP_FAILED(9), NATIVE_FAILED(10),
}

enum class InitRcTimingVerdict {
    NOT_EVALUATED, INCONCLUSIVE, NO_REPEATABLE_INTERACTION, REPEATABLE_INTERACTION,
}

/** Complete batch durations, indexed by (comm == init) * 2 + (filename == init.rc). */
data class InitRcTimingRound(
    val normalControlNanos: Long,
    val normalTargetNanos: Long,
    val initControlNanos: Long,
    val initTargetNanos: Long,
) {
    val durations: List<Long> get() = listOf(
        normalControlNanos, normalTargetNanos, initControlNanos, initTargetNanos,
    )
}

data class InitRcTimingObservation(
    val collection: InitRcTimingCollection = InitRcTimingCollection.NOT_RUN,
    val rounds: List<InitRcTimingRound> = emptyList(),
    val iterations: Int = 128,
    val cpu: Int = -1,
    val errorNumber: Int = 0,
    val cleanupErrorNumber: Int = 0,
    val cleanupCompleted: Boolean = false,
    val failureDetail: String = "",
) {
    /** Necessary sample invariants shared by wire validation and typed report analysis. */
    val hasCompleteSample: Boolean get() = rounds.size == 32 && iterations == 128 && cpu >= 0 &&
        rounds.all { round -> round.durations.all { it in 1..1_000_000_000L } } &&
        rounds.sumOf { it.durations.sum() } < 1_000_000_000L

    val analysis: InitRcTimingAnalysis get() = analyzeInitRcTiming(this)
}

data class InitRcTimingAnalysis(
    val verdict: InitRcTimingVerdict,
    val medianContrastNanos: Double = 0.0,
    val madNanos: Double = 0.0,
    val positiveRounds: Int = 0,
    val orderMediansNanos: List<Double> = emptyList(),
)
