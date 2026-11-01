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

data class HmaUidPermissionEvidence(val uid: Int, val permissions: List<String>)

data class HmaUidPermissionObservation(
    val firstUid: Int,
    val checked: Int,
    val controlsPassed: Boolean,
    val evidence: List<HmaUidPermissionEvidence> = emptyList(),
    val unstableCandidates: Int = 0,
    val candidateLimitReached: Boolean = false,
    val failureState: HmaCheckState? = null,
    val failureDetail: String = "",
)

object HmaUidPermissionPolicy {
    fun evaluate(observation: HmaUidPermissionObservation): HmaBehaviorCheck = with(observation) {
        val validRange = firstUid >= 10000 && firstUid % 100000 == 10000 && checked in 0..10000
        val validEvidence = evidence.all { item ->
            item.uid.toLong() in firstUid.toLong() until firstUid.toLong() + checked &&
                item.permissions.isNotEmpty() && item.permissions.all { it in PERMISSIONS }
        } && evidence.map { it.uid }.distinct().size == evidence.size
        val valid = controlsPassed && validRange && validEvidence
        val state = when {
            !valid -> failureState ?: HmaCheckState.INCONCLUSIVE
            evidence.isNotEmpty() -> HmaCheckState.EXPERIMENTAL_ANOMALY
            failureState != null -> failureState
            unstableCandidates > 0 -> HmaCheckState.INCONCLUSIVE
            checked < 10000 || candidateLimitReached -> HmaCheckState.PARTIAL
            else -> HmaCheckState.CONSISTENT
        }
        val findings = if (valid) evidence else emptyList()
        return HmaBehaviorCheck(
            HmaCheckKind.UID_PERMISSION_VISIBILITY, state,
            "$checked/10000 ordinary app UIDs queried for this Android user; first UID=$firstUid; " +
                "controls passed=$controlsPassed; ${findings.size} fresh permission/association discrepancy(s); " +
                "unstable candidates=$unstableCandidates; candidate limit reached=$candidateLimitReached. " +
                "Non-instant permissions: ${PERMISSIONS.joinToString()}. " +
                findings.joinToString { "UID ${it.uid}: ${it.permissions.joinToString()}" } +
                " Experimental evidence only; this does not identify HMA or a package. " +
                "A negative result does not exclude packages without these permissions. " +
                "Failure=${failureState?.label ?: "none"}; $failureDetail",
            uids = findings.map { it.uid },
            uidPermissionEvidence = findings,
        )
    }

    // Android 15–17 manifests omit the instant protection flag for these normal permissions.
    // PermissionService rejects non-instant permissions for instant apps, even if requested.
    val PERMISSIONS: List<String> = listOf(
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.REORDER_TASKS",
    )
}

/** Correlation annotates the shared UID without turning one package-filtering surface into votes. */
object HmaUidEvidenceCorrelation {
    fun annotate(checks: List<HmaBehaviorCheck>): List<HmaBehaviorCheck> {
        val taskUids = checks.filter { it.kind == HmaCheckKind.UID_TASK_VISIBILITY }.flatMap { it.uids }.toSet()
        val permissionUids = checks.filter { it.kind == HmaCheckKind.UID_PERMISSION_VISIBILITY }.flatMap { it.uids }.toSet()
        val shared = taskUids.intersect(permissionUids).sorted()
        if (shared.isEmpty()) return checks
        return checks.map { check ->
            if (check.kind !in setOf(HmaCheckKind.UID_TASK_VISIBILITY, HmaCheckKind.UID_PERMISSION_VISIBILITY)) check
            else check.copy(detail = check.detail + " Shared task/permission UID(s): ${shared.joinToString()}. " +
                "Both comparisons use package associations; correlation adds no independent HMA confidence.")
        }
    }
}
