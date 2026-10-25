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

data class KernelSuTimingCpuSnapshot(
    val present: List<Int>? = null,
    val online: List<Int>? = null,
    val allowed: List<Int>? = null,
    val detail: String = "",
) {
    init {
        listOfNotNull(present, online, allowed).forEach { cpus ->
            require(cpus.size <= 1024 && cpus == cpus.distinct().sorted())
            require(cpus.all { it in 0..1023 })
        }
    }
    val complete: Boolean get() = present != null && online != null && allowed != null
    val eligible: List<Int> get() = present.orEmpty().filter { it in online.orEmpty() && it in allowed.orEmpty() }
}

data class KernelSuTimingSyscallSummary(
    val outcomes: Map<Long, Int>,
    val otherOutcomes: Int = 0,
    val retriedSamples: Int = 0,
    val totalRetries: Int = 0,
    val maximumRetries: Int = 0,
    val retryLimitSamples: Int = 0,
) {
    init {
        require(outcomes.size in 1..8 && outcomes.values.all { it in 1..10000 })
        require(otherOutcomes in 0..10000 && outcomes.values.sum() + otherOutcomes == 10000)
        require(retriedSamples in 0..10000 && maximumRetries in 0..3)
        require(totalRetries in retriedSamples..(retriedSamples * 3))
        require(totalRetries >= maximumRetries && totalRetries <= retriedSamples * maximumRetries)
        require((retriedSamples == 0) == (maximumRetries == 0))
        require(retryLimitSamples in 0..retriedSamples)
    }
    // ACK prctl rejects an unknown option with EINVAL unless an earlier hook
    // intercepts it. Even identical errno values do not establish identical paths.
    val expectedRejection: Boolean
        get() = outcomes == mapOf(-22L to 10000) && otherOutcomes == 0 && totalRetries == 0
}

data class KernelSuTimingWindowEvidence(
    val before: KernelSuTimingCpuSnapshot,
    val after: KernelSuTimingCpuSnapshot,
    val workerAllowed: List<Int>,
    val outcomes: List<KernelSuTimingSyscallSummary>,
    val counterFrequencyHz: ULong,
) {
    init {
        require(workerAllowed == workerAllowed.distinct().sorted() && workerAllowed.all { it in 0..1023 })
        require(outcomes.size in listOf(0, 1, 6))
    }
    val stable: Boolean
        get() = before.complete && after.complete && before == after && workerAllowed == before.allowed
    val expectedOutcomes: Boolean get() = outcomes.isNotEmpty() && outcomes.all { it.expectedRejection }
}
