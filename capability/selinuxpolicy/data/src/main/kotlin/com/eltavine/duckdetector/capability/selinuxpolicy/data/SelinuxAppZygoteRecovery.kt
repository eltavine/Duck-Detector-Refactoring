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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

internal object SelinuxAppZygoteRecovery {
    const val STALE_PRELOAD = "App Zygote preload belongs to an earlier scan."
    private const val MISSING_PARENT = "App Zygote parent PID unavailable for recovery."
    private const val CARRIERS_NOT_RETIRED = "App Zygote carrier children did not retire before recovery deadline."
    private const val SAME_PARENT = "App Zygote was reused after waiting for retirement."
    private const val UNKNOWN_PARENT = "Replacement App Zygote parent PID unavailable."
    const val GENERATION_ALREADY_CONSUMED = "App Zygote preload generation was already consumed."
    const val GENERATION_FENCE_UNAVAILABLE = "App Zygote generation fence unavailable."

    fun stale(origin: SelinuxCarrierProvenance?, scanStartedNanos: Long): Boolean =
        origin != null && origin.startedNanos < scanStartedNanos

    fun recoverable(reason: String?): Boolean = reason == STALE_PRELOAD ||
        reason == SelinuxContextValidityCarrierService.PRELOAD_PAYLOAD_UNAVAILABLE ||
        reason == "App Zygote preload APK generation mismatch." ||
        reason == "App Zygote preload parent PID mismatch." ||
        reason == "App Zygote preload schema mismatch." ||
        reason == "App Zygote preload version code mismatch." ||
        reason == "App Zygote preload build revision mismatch." ||
        reason == GENERATION_ALREADY_CONSUMED

    /**
     * The caller holds the global start gate while [awaitRetirement] drains known children and
     * observes the framework's delayed-retirement window. Existing connections can still finish
     * and close because those operations do not acquire the start gate.
     */
    suspend fun <T> recover(
        first: T,
        reason: (T) -> String?,
        parentPid: (T) -> Int?,
        awaitRetirement: suspend (Int) -> Boolean,
        retry: suspend () -> T,
        failure: (String) -> T,
    ): T {
        if (!recoverable(reason(first))) return first
        val previous = parentPid(first) ?: return failure(MISSING_PARENT)
        if (!awaitRetirement(previous)) return failure(CARRIERS_NOT_RETIRED)
        val second = retry()
        if (reason(second) != null) return second
        val replacement = parentPid(second)
            ?: return failure(UNKNOWN_PARENT)
        return if (replacement != previous) second else failure(SAME_PARENT)
    }
}
