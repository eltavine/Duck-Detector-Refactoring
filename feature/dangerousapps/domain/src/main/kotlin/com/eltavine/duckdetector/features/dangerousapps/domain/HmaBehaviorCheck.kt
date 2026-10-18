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

enum class HmaCheckKind(val label: String) {
    BROADCAST_CROSS_USER("Broadcast cross-user exception"),
    BROADCAST_RESULT_COMPLETION("Broadcast final callback completion"),
    BROADCAST_RESULT_TO("Broadcast final result callback"),
    PACKAGE_INFO_EXCEPTION("getPackageInfo exception"),
    APPLICATION_INFO_EXCEPTION("getApplicationInfo exception"),
    UID_TASK_VISIBILITY("getpriority UID visibility"),
    SECCOMP_UID_FILTER("Seccomp getpriority interference"),
}

enum class HmaCheckState(val label: String) {
    CONSISTENT("Consistent in evaluated scope"),
    INCONSISTENT("Behavior mismatch observed"),
    TIMING_ANOMALY("Repeated callback timeout (lower confidence)"),
    INCONCLUSIVE("Inconclusive"),
    UNAVAILABLE("Unavailable"),
    UNSUPPORTED("Unsupported"),
    PERMISSION_LIMITED("Permission limited"),
    PARTIAL("Partially evaluated"),
}

data class HmaBehaviorCheck(
    val kind: HmaCheckKind,
    val state: HmaCheckState,
    val detail: String,
    val packages: List<String> = emptyList(),
    val uids: List<Int> = emptyList(),
)

enum class HmaCallOutcome { SECURITY_EXCEPTION, RETURNED, NAME_NOT_FOUND, FAILED, UNAVAILABLE }

data class HmaExceptionObservation(
    val packageName: String,
    val first: HmaCallOutcome,
    val repeat: HmaCallOutcome,
)

enum class HmaCallbackFailure { NONE, TIMED_OUT, PERMISSION_DENIED, FAILED }

data class HmaCallbackObservation(
    val received: Boolean,
    val ordered: Boolean = false,
    val sticky: Boolean = false,
    val payloadPreserved: Boolean = false,
    val intentPreserved: Boolean = false,
    val failure: HmaCallbackFailure = HmaCallbackFailure.NONE,
) {
    val consistent: Boolean get() = received && !ordered && !sticky && payloadPreserved &&
        intentPreserved && failure == HmaCallbackFailure.NONE
}

object HmaBehaviorPolicy {
    fun targetOrder(packages: List<String>, corroborated: Set<String>): List<String> =
        packages.distinct().sortedBy { it !in corroborated }

    fun exceptions(
        kind: HmaCheckKind,
        before: HmaCallOutcome,
        after: HmaCallOutcome,
        observations: List<HmaExceptionObservation>,
    ): HmaBehaviorCheck {
        if (before != HmaCallOutcome.SECURITY_EXCEPTION || after != HmaCallOutcome.SECURITY_EXCEPTION) {
            val state = if (before == HmaCallOutcome.UNAVAILABLE || after == HmaCallOutcome.UNAVAILABLE)
                HmaCheckState.UNAVAILABLE else HmaCheckState.INCONCLUSIVE
            return HmaBehaviorCheck(kind, state,
                "Caller-package control outcomes: $before / $after; both must throw SecurityException.")
        }
        val mismatch = observations.filter { it.first.isSkippedException() && it.repeat.isSkippedException() }
        val incomplete = observations.any { it.first != it.repeat || it.first in setOf(HmaCallOutcome.FAILED, HmaCallOutcome.UNAVAILABLE) }
        val outcomes = observations.flatMap { listOf(it.first, it.repeat) }
        val counts = HmaCallOutcome.entries.joinToString { outcome -> "$outcome=${outcomes.count { it == outcome }}" }
        return HmaBehaviorCheck(kind, when {
            mismatch.isNotEmpty() -> HmaCheckState.INCONSISTENT
            incomplete || observations.isEmpty() -> HmaCheckState.INCONCLUSIVE
            else -> HmaCheckState.CONSISTENT
        }, "${observations.size} package(s) checked twice between permission controls; ${mismatch.size} repeated exception mismatch(es). Outcomes: $counts.",
            packages = mismatch.map { it.packageName })
    }

    private fun HmaCallOutcome.isSkippedException(): Boolean =
        this == HmaCallOutcome.RETURNED || this == HmaCallOutcome.NAME_NOT_FOUND
}
