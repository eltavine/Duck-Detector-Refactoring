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

enum class KernelSuTimingCollection {
    NOT_RUN, COLLECTED, UNSUPPORTED, UNAVAILABLE, NONINTERACTIVE, CANCELLED, TIMED_OUT,
    PREFLIGHT_REJECTED, PARTIAL, WORKER_DIED, PROTOCOL_ERROR,
}

enum class KernelSuTimingVerdict {
    NOT_EVALUATED, INCONCLUSIVE, NOT_OBSERVED, REPEATED_PATTERN,
}

enum class KernelSuTimingPreflightStatus {
    NOT_RUN, ACCEPTED, MALFORMED, TOO_MANY_BINS, EXCESSIVE_MINIMUM,
}

data class KernelSuTimingPreflight(
    val status: KernelSuTimingPreflightStatus = KernelSuTimingPreflightStatus.NOT_RUN,
    val binCount: Int = 0,
    val minimumTicks: ULong? = null,
) {
    companion object {
        fun fromFrequencies(frequencies: List<ULong>): KernelSuTimingPreflight {
            if (frequencies.isEmpty() || frequencies.size % 2 != 0 || frequencies.size > 20000) {
                return KernelSuTimingPreflight(KernelSuTimingPreflightStatus.MALFORMED)
            }
            val bins = frequencies.chunked(2)
            if (bins.any { it[1] == 0uL || it[1] > KernelSuTimingProfile.SAMPLE_COUNT.toULong() } ||
                bins.sumOf { it[1] } != KernelSuTimingProfile.SAMPLE_COUNT.toULong() ||
                bins.map { it[0] }.distinct().size != bins.size) {
                return KernelSuTimingPreflight(KernelSuTimingPreflightStatus.MALFORMED)
            }
            val minimum = bins.minOf { it[0] }
            val status = when {
                bins.size > 750 -> KernelSuTimingPreflightStatus.TOO_MANY_BINS
                minimum > 135uL -> KernelSuTimingPreflightStatus.EXCESSIVE_MINIMUM
                else -> KernelSuTimingPreflightStatus.ACCEPTED
            }
            return KernelSuTimingPreflight(status, bins.size, minimum)
        }
    }
}

enum class KernelSuTimingCoreStatus {
    MEASURED, AFFINITY_FAILED, CPU_MISMATCH, TIMER_UNAVAILABLE, SAMPLING_FAILED, CLEANUP_FAILED,
}

data class KernelSuTimingCoreAttempt(
    val requestedCpu: Int,
    val actualCpu: Int?,
    val status: KernelSuTimingCoreStatus,
    val rounds: List<KernelSuTimingAnalysis> = emptyList(),
) {
    init {
        require(requestedCpu in 0 until KernelSuTimingProfile.MAXIMUM_CORES)
        require(rounds.size <= KernelSuTimingProfile.REQUIRED_ROUNDS)
        require(rounds.dropLast(1).all { it.matched })
    }

    val valid: Boolean
        get() = status == KernelSuTimingCoreStatus.MEASURED && actualCpu == requestedCpu
    val confirmed: Boolean
        get() = valid && rounds.size == KernelSuTimingProfile.REQUIRED_ROUNDS && rounds.all { it.matched }
    val completed: Boolean get() = valid && (confirmed || rounds.lastOrNull()?.matched == false)
}

data class KernelSuTimingObservation(
    val collection: KernelSuTimingCollection = KernelSuTimingCollection.NOT_RUN,
    val preflight: KernelSuTimingPreflight = KernelSuTimingPreflight(),
    val enumeratedCpus: List<Int> = emptyList(),
    val attempts: List<KernelSuTimingCoreAttempt> = emptyList(),
    val counterFrequencyHz: ULong? = null,
    val cleanupCompleted: Boolean = false,
    val detail: String = "",
) {
    init {
        require(enumeratedCpus.size <= KernelSuTimingProfile.MAXIMUM_CORES)
        require(enumeratedCpus == enumeratedCpus.indices.toList())
        require(attempts.size <= KernelSuTimingProfile.MAXIMUM_CORES)
        require(attempts.map { it.requestedCpu }.distinct().size == attempts.size)
        require(attempts.all { it.requestedCpu in enumeratedCpus })
    }

    val verdict: KernelSuTimingVerdict
        get() {
            if (collection == KernelSuTimingCollection.NOT_RUN || collection == KernelSuTimingCollection.UNSUPPORTED) {
                return KernelSuTimingVerdict.NOT_EVALUATED
            }
            if (collection !in setOf(KernelSuTimingCollection.COLLECTED, KernelSuTimingCollection.PARTIAL,
                    KernelSuTimingCollection.NONINTERACTIVE) ||
                !cleanupCompleted || preflight.status != KernelSuTimingPreflightStatus.ACCEPTED ||
                counterFrequencyHz == null || counterFrequencyHz == 0uL) {
                return KernelSuTimingVerdict.INCONCLUSIVE
            }
            if (attempts.any { it.confirmed }) return KernelSuTimingVerdict.REPEATED_PATTERN
            if (collection != KernelSuTimingCollection.COLLECTED || enumeratedCpus.isEmpty() ||
                attempts.map { it.requestedCpu }.toSet() != enumeratedCpus.toSet() ||
                attempts.any { !it.completed }) {
                return KernelSuTimingVerdict.INCONCLUSIVE
            }
            return KernelSuTimingVerdict.NOT_OBSERVED
        }
}
