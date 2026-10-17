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

package com.eltavine.duckdetector.features.dangerousapps.domain

data class HmaCallbackComparison(
    val packageName: String,
    val first: HmaCallbackObservation,
    val repeat: HmaCallbackObservation,
    val before: HmaCallbackObservation,
    val between: HmaCallbackObservation,
    val after: HmaCallbackObservation,
) {
    val controlsPassed: Boolean get() = before.consistent && between.consistent && after.consistent
}

object HmaBroadcastPolicy {
    fun evaluate(
        initialControl: HmaCallbackObservation,
        observations: List<HmaCallbackComparison>,
        expectedCount: Int,
        budgetExpired: Boolean = false,
    ): List<HmaBehaviorCheck> {
        val kinds = listOf(HmaCheckKind.BROADCAST_RESULT_COMPLETION, HmaCheckKind.BROADCAST_RESULT_TO)
        if (!initialControl.consistent) return kinds.map {
            HmaBehaviorCheck(it, failureState(listOf(initialControl)),
                "Initial caller-package callback control failed (${initialControl.controlDetail()}); target calls were skipped.")
        }
        val controlled = observations.filter { it.controlsPassed }
        val semanticMismatches = controlled.filter {
            it.first.received && it.repeat.received &&
                it.first.failure == HmaCallbackFailure.NONE && it.repeat.failure == HmaCallbackFailure.NONE &&
                !it.first.consistent && !it.repeat.consistent
        }
        val timeouts = controlled.filter { it.first.timedOut && it.repeat.timedOut }
        val targets = observations.flatMap { listOf(it.first, it.repeat) }
        val controls = observations.flatMap { listOf(it.before, it.between, it.after) }
        val noCompletion = controlled.any { !it.first.received || !it.repeat.received }
        val baseState = when {
            observations.isEmpty() -> if (budgetExpired) HmaCheckState.PARTIAL else HmaCheckState.INCONCLUSIVE
            observations.any { !it.controlsPassed } -> failureState(controls)
            targets.any { it.failure != HmaCallbackFailure.NONE } -> failureState(targets)
            noCompletion -> HmaCheckState.INCONCLUSIVE
            observations.size < expectedCount -> HmaCheckState.PARTIAL
            else -> HmaCheckState.CONSISTENT
        }
        val detail = "${observations.size}/$expectedCount target(s) completed paired calls; " +
            "${controlled.size} passed caller controls before, between and after. " +
            "Target outcomes: ${targets.count { it.timedOut }} timeout(s), " +
            "${targets.count { it.failure == HmaCallbackFailure.PERMISSION_DENIED }} denial(s), " +
            "${targets.count { it.failure == HmaCallbackFailure.FAILED }} failure(s). " +
            "Batch deadline reached=$budgetExpired. Failed controls: " +
            controls.filter { !it.consistent }.joinToString { it.controlDetail() }.ifEmpty { "none" } + "."
        return listOf(
            HmaBehaviorCheck(HmaCheckKind.BROADCAST_RESULT_COMPLETION,
                if (timeouts.isNotEmpty()) HmaCheckState.TIMING_ANOMALY else baseState,
                "$detail ${timeouts.size} target(s) repeatedly missed the callback deadline with passing interleaved controls. " +
                    "This is a lower-confidence timing observation, not proof of a hook or permanent callback loss.",
                packages = timeouts.map { it.packageName }),
            HmaBehaviorCheck(HmaCheckKind.BROADCAST_RESULT_TO, when {
                semanticMismatches.isNotEmpty() -> HmaCheckState.INCONSISTENT
                controlled.any { !it.first.consistent || !it.repeat.consistent } &&
                    baseState in setOf(HmaCheckState.CONSISTENT, HmaCheckState.PARTIAL) -> HmaCheckState.INCONCLUSIVE
                else -> baseState
            }, "$detail ${semanticMismatches.size} repeated flag, result-payload or callback-intent mismatch(es). " +
                "Missing callbacks cannot establish a semantic mismatch.",
                packages = semanticMismatches.map { it.packageName }),
        )
    }

    private val HmaCallbackObservation.timedOut: Boolean
        get() = !received && failure == HmaCallbackFailure.TIMED_OUT

    private fun HmaCallbackObservation.controlDetail(): String =
        "received=$received, ordered=$ordered, sticky=$sticky, result=$payloadPreserved, intent=$intentPreserved, failure=$failure"

    private fun failureState(observations: List<HmaCallbackObservation>): HmaCheckState = when {
        observations.any { it.failure == HmaCallbackFailure.PERMISSION_DENIED } -> HmaCheckState.PERMISSION_LIMITED
        observations.any { it.failure == HmaCallbackFailure.FAILED } -> HmaCheckState.UNAVAILABLE
        else -> HmaCheckState.INCONCLUSIVE
    }
}
