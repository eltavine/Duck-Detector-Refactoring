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

data class HmaUidVisibilityObservation(
    val complete: Boolean,
    val checked: Int,
    val firstUid: Int,
    val taskUids: Set<Int>,
    val callerUid: Int,
    val callerAssociationBefore: Boolean,
    val callerAssociationAfter: Boolean,
    val unassociated: List<Int>,
    val verificationFailed: Boolean,
    val verificationLimitReached: Boolean,
)

object HmaUidVisibilityPolicy {
    fun evaluate(observation: HmaUidVisibilityObservation): HmaBehaviorCheck = with(observation) {
        // The caller stays alive during collection, including any partial prefix that reached it.
        val callerWasQueried = callerUid >= firstUid && callerUid.toLong() < firstUid.toLong() + checked
        val controlsPassed = callerAssociationBefore && callerAssociationAfter &&
            (!(complete || callerWasQueried) || callerUid in taskUids)
        val state = when {
            !controlsPassed -> HmaCheckState.INCONCLUSIVE
            unassociated.isNotEmpty() -> HmaCheckState.INCONSISTENT
            verificationFailed -> HmaCheckState.INCONCLUSIVE
            !complete || verificationLimitReached -> HmaCheckState.PARTIAL
            else -> HmaCheckState.CONSISTENT
        }
        HmaBehaviorCheck(HmaCheckKind.UID_TASK_VISIBILITY, state,
            "$checked/10000 ordinary app UIDs queried for this Android user; ${taskUids.size} task UID(s), " +
                "${unassociated.size} repeatedly lacked a visible package association. " +
                "First UID=$firstUid; caller queried=$callerWasQueried; controls passed=$controlsPassed; " +
                "recheck failure=$verificationFailed; recheck limit=$verificationLimitReached. " +
                "This does not identify a hidden package or HMA.",
            uids = if (controlsPassed) unassociated else emptyList())
    }
}
