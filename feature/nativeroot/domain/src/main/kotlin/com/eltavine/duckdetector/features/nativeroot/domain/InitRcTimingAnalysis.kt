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

fun analyzeInitRcTiming(observation: InitRcTimingObservation): InitRcTimingAnalysis {
    if (observation.collection != InitRcTimingCollection.COLLECTED || !observation.cleanupCompleted ||
        observation.errorNumber != 0 || observation.cleanupErrorNumber != 0
    ) return InitRcTimingAnalysis(InitRcTimingVerdict.NOT_EVALUATED)
    // The native budget is one second. A malformed, incomplete or unpinned run cannot be a control.
    if (!observation.hasCompleteSample) return InitRcTimingAnalysis(InitRcTimingVerdict.INCONCLUSIVE)

    val contrasts = observation.rounds.map {
        ((it.initTargetNanos.toDouble() - it.initControlNanos) -
            (it.normalTargetNanos.toDouble() - it.normalControlNanos)) / observation.iterations
    }
    val median = contrasts.median()
    val mad = contrasts.map { abs(it - median) }.median()
    val orders = (0..3).map { order -> contrasts.filterIndexed { index, _ -> index % 4 == order } }
    val orderMedians = orders.map { it.median() }
    val positive = contrasts.count { it > 0 }
    // Descriptive repeatability only. These provisional rules have no calibrated false-positive
    // bound; samples need not be independent and another comm-aware hook can reproduce the effect.
    val repeatable = positive >= 28 && orders.all { group -> group.count { it > 0 } >= 6 } &&
        orderMedians.all { it > 0 } && contrasts.take(16).median() > 0 &&
        contrasts.drop(16).median() > 0 && median > 3 * mad
    return InitRcTimingAnalysis(
        verdict = if (repeatable) InitRcTimingVerdict.REPEATABLE_INTERACTION
            else InitRcTimingVerdict.NO_REPEATABLE_INTERACTION,
        medianContrastNanos = median,
        madNanos = mad,
        positiveRounds = positive,
        orderMediansNanos = orderMedians,
    )
}

private fun List<Double>.median(): Double {
    val ordered = sorted()
    return (ordered[(size - 1) / 2] + ordered[size / 2]) / 2
}
