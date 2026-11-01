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

package com.eltavine.duckdetector.features.rootmanagers.domain

enum class InstallerCanaryState {
    DISABLED, UNSUPPORTED, UNAVAILABLE, USER_ACTION_REQUIRED, THROTTLED, TIMED_OUT,
    INCONCLUSIVE, UNEXPECTED_SUCCESS, PERMISSION_OWNER_OBSERVED, PERMISSION_NOT_OBSERVED,
}

/** A registry observation, not authenticated manager identity or proof of root access. */
data class InstallerCanaryObservation(
    val state: InstallerCanaryState = InstallerCanaryState.DISABLED,
    val ownerPackageName: String? = null,
    val detail: String? = null,
    val locations: List<InstallerCanaryLocation> = emptyList(),
    /** Errno counts include ENOENT: a namespace-hidden path is not evidence of absence. */
    val directoryErrors: Map<Int, Int> = emptyMap(),
) {
    val evaluated: Boolean get() = state == InstallerCanaryState.PERMISSION_OWNER_OBSERVED ||
        state == InstallerCanaryState.PERMISSION_NOT_OBSERVED
}

data class InstallerCanaryLocation(val userId: Int, val uid: Int) {
    val appId: Int get() = uid % 100_000
}

/** Candidate name only: rebuilding with another applicationId may change it. */
object InstallerCanaryTarget {
    const val PERMISSION = "me.weishu.kernelsu.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
}
