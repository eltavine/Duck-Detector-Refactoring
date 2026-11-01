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
    init {
        require(binCount in 0..10000)
        require(status != KernelSuTimingPreflightStatus.ACCEPTED ||
            (binCount in 1..750 && minimumTicks != null && minimumTicks <= MAXIMUM_MINIMUM_TICKS))
    }
    companion object {
        // Preserve the original applicability gate in counter ticks, independently for each CPU.
        private const val MAXIMUM_MINIMUM_TICKS: ULong = 135uL

        fun fromFrequencies(frequencies: List<ULong>): KernelSuTimingPreflight {
            if (frequencies.isEmpty() || frequencies.size % 2 != 0 || frequencies.size > 20000) {
                return KernelSuTimingPreflight(KernelSuTimingPreflightStatus.MALFORMED)
            }
            val bins = frequencies.chunked(2)
            if (bins.any { it[1] == 0uL || it[1] > 10000uL } || bins.sumOf { it[1] } != 10000uL ||
                bins.map { it[0] }.distinct().size != bins.size) {
                return KernelSuTimingPreflight(KernelSuTimingPreflightStatus.MALFORMED)
            }
            val minimumTicks = bins.minOf { it[0] }
            val status = when {
                bins.size > 750 -> KernelSuTimingPreflightStatus.TOO_MANY_BINS
                minimumTicks > MAXIMUM_MINIMUM_TICKS -> KernelSuTimingPreflightStatus.EXCESSIVE_MINIMUM
                else -> KernelSuTimingPreflightStatus.ACCEPTED
            }
            return KernelSuTimingPreflight(status, bins.size, minimumTicks)
        }
    }
}

enum class KernelSuTimingCoreStatus {
    MEASURED, AFFINITY_FAILED, CPU_MISMATCH, TIMER_UNAVAILABLE, SAMPLING_FAILED, CLEANUP_FAILED,
    PREFLIGHT_REJECTED, OUTCOME_CONTAMINATED, INSUFFICIENT_SUPPORT, ELIGIBILITY_CHANGED,
}

data class KernelSuTimingCoreAttempt(
    val requestedCpu: Int,
    val actualCpu: Int?,
    val status: KernelSuTimingCoreStatus,
    val rounds: List<KernelSuTimingAnalysis> = emptyList(),
    val preflight: KernelSuTimingPreflight = KernelSuTimingPreflight(),
    val windows: List<KernelSuTimingWindowEvidence> = emptyList(),
) {
    init {
        require(requestedCpu in 0..1023)
        require(rounds.size <= KernelSuTimingProfile.REQUIRED_ROUNDS)
        require(windows.size <= KernelSuTimingProfile.REQUIRED_ROUNDS + 1)
        require(rounds.dropLast(1).all { it.matched })
    }
    val valid: Boolean
        get() = status == KernelSuTimingCoreStatus.MEASURED && actualCpu == requestedCpu &&
            preflight.status == KernelSuTimingPreflightStatus.ACCEPTED && windows.size == rounds.size + 1 &&
            windows.first().outcomes.size == 1 && windows.drop(1).all { it.outcomes.size == 6 } &&
            windows.all { it.stable && it.expectedOutcomes && requestedCpu in it.before.eligible &&
                it.before == windows.first().before && it.counterFrequencyHz != 0uL &&
                it.counterFrequencyHz == windows.first().counterFrequencyHz } && rounds.all { it.valid }
    val confirmed: Boolean
        get() = valid && rounds.size == KernelSuTimingProfile.REQUIRED_ROUNDS && rounds.all { it.matched }
    val completed: Boolean get() = valid && (confirmed || rounds.lastOrNull()?.matched == false)
}

data class KernelSuTimingObservation(
    val collection: KernelSuTimingCollection = KernelSuTimingCollection.NOT_RUN,
    val initialCpus: KernelSuTimingCpuSnapshot = KernelSuTimingCpuSnapshot(),
    val attempts: List<KernelSuTimingCoreAttempt> = emptyList(),
    val finalCpus: KernelSuTimingCpuSnapshot? = null,
    val cleanupCompleted: Boolean = false,
    val detail: String = "",
) {
    init {
        require(attempts.size <= KernelSuTimingProfile.MAXIMUM_CORES)
        require(attempts.map { it.requestedCpu }.distinct().size == attempts.size)
        require(attempts.all { it.requestedCpu in initialCpus.present.orEmpty() })
    }
    val sampledCpus: List<Int> get() = attempts.filter { core -> core.windows.drop(1).any { it.outcomes.size == 6 } }.map { it.requestedCpu }
    val coverageStable: Boolean
        get() = initialCpus.complete && finalCpus == initialCpus &&
            attempts.flatMap { it.windows }.all { it.stable && it.before == initialCpus }
    val verdict: KernelSuTimingVerdict
        get() {
            if (collection in listOf(KernelSuTimingCollection.NOT_RUN, KernelSuTimingCollection.UNSUPPORTED)) {
                return KernelSuTimingVerdict.NOT_EVALUATED
            }
            if (collection !in listOf(KernelSuTimingCollection.COLLECTED, KernelSuTimingCollection.PARTIAL,
                    KernelSuTimingCollection.NONINTERACTIVE) || !cleanupCompleted) {
                return KernelSuTimingVerdict.INCONCLUSIVE
            }
            if (attempts.any { it.confirmed }) return KernelSuTimingVerdict.REPEATED_PATTERN
            // Absence continues to require every present CPU, including CPUs
            // excluded by offline state, affinity/cpuset or the bounded budget.
            if (collection != KernelSuTimingCollection.COLLECTED || !coverageStable ||
                initialCpus.present.isNullOrEmpty() ||
                attempts.map { it.requestedCpu }.toSet() != initialCpus.present.toSet() ||
                attempts.any { !it.completed }) return KernelSuTimingVerdict.INCONCLUSIVE
            return KernelSuTimingVerdict.NOT_OBSERVED
        }
}
