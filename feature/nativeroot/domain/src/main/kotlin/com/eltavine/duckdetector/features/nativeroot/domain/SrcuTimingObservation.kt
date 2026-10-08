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

/** Collection and interpretation are separate: a completed experiment can be inconclusive. */
enum class SrcuTimingCollection {
    NOT_REQUESTED, UNSUPPORTED_ANDROID, UNSUPPORTED_KERNEL, PERMISSION_TREE_UNAVAILABLE,
    COLLECTED, NATIVE_FAILED, TRIGGER_FAILED, CLEANUP_FAILED, IPC_FAILED, TIMED_OUT, BUSY,
}

enum class SrcuTimingVerdict { NOT_EVALUATED, INCONCLUSIVE, NOT_OBSERVED, REPEATABLE_DELAY }

enum class SrcuCloseStage { OK, INIT_FAILED, WATCH_FAILED, CLOCK_FAILED, CLOSE_FAILED, THREAD_FAILED }

data class SrcuCloseSample(
    val beginNanos: Long,
    val endNanos: Long,
    val stage: SrcuCloseStage,
    val errorNumber: Int = 0,
) {
    val durationNanos: Long get() = endNanos - beginNanos
    val usable: Boolean get() = stage == SrcuCloseStage.OK && beginNanos > 0 && endNanos >= beginNanos
}

data class SrcuTimingWindow(
    val beginNanos: Long,
    val endNanos: Long,
    val saturated: Boolean,
    val samples: List<SrcuCloseSample>,
) {
    // User-space overlap is only a candidate overlap with the kernel reader, not proof of it.
    val usableSamples: List<SrcuCloseSample> get() = samples.filter {
        it.usable && it.beginNanos >= beginNanos && it.beginNanos < endNanos
    }
    val complete: Boolean get() = beginNanos > 0 && endNanos > beginNanos && !saturated &&
        samples.isNotEmpty() && samples.all { it.usable }
}

data class SrcuTimingRound(
    val idle: SrcuTimingWindow,
    val stimulated: SrcuTimingWindow,
    val sequential: SrcuTimingWindow,
)

data class SrcuTimingObservation(
    val collection: SrcuTimingCollection = SrcuTimingCollection.NOT_REQUESTED,
    val rounds: List<SrcuTimingRound> = emptyList(),
    val kernelRelease: String = "",
    val failureDetail: String = "",
    val cleanupCompleted: Boolean = false,
    val failedWindow: SrcuTimingWindow? = null,
) {
    val analysis: SrcuTimingAnalysis get() = analyzeSrcuTiming(this)
    val requested: Boolean get() = collection != SrcuTimingCollection.NOT_REQUESTED
}

data class SrcuTimingAnalysis(
    val verdict: SrcuTimingVerdict,
    val usableRounds: Int = 0,
    val delayedRounds: Int = 0,
    val idleP95Nanos: Long = 0,
    val stimulatedP95Nanos: Long = 0,
    val sequentialP95Nanos: Long = 0,
)
