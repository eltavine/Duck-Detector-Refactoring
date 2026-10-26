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

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import kotlinx.coroutines.delay

internal object SelinuxAppZygoteRecovery {
    const val STALE_PRELOAD = "App Zygote preload belongs to an earlier scan."
    private const val MISSING_PARENT = "App Zygote parent PID unavailable for recovery."
    private const val PARENT_NOT_RETIRED = "App Zygote parent did not exit before recovery deadline."
    private const val SAME_PARENT = "App Zygote was reused after waiting for retirement."
    private const val UNKNOWN_PARENT = "Replacement App Zygote parent PID unavailable."

    fun stale(origin: SelinuxCarrierProvenance?, scanStartedNanos: Long): Boolean =
        origin != null && origin.startedNanos < scanStartedNanos

    fun recoverable(reason: String?): Boolean = reason == STALE_PRELOAD ||
        reason == SelinuxContextValidityCarrierService.PRELOAD_PAYLOAD_UNAVAILABLE ||
        reason == "App Zygote preload APK generation mismatch." ||
        reason == "App Zygote preload parent PID mismatch."

    /** Waiting never holds the start gate: other carriers may finish and release the old parent. */
    suspend fun <T> recover(
        first: T,
        reason: (T) -> String?,
        parentPid: (T) -> Int?,
        awaitExit: suspend (Int) -> Boolean,
        retry: suspend () -> T,
        failure: (String) -> T,
    ): T {
        if (!recoverable(reason(first))) return first
        val previous = parentPid(first) ?: return failure(MISSING_PARENT)
        if (!awaitExit(previous)) return failure(PARENT_NOT_RETIRED)
        val second = retry()
        val replacement = parentPid(second)
            ?: return if (reason(second) != null) second else failure(UNKNOWN_PARENT)
        return if (replacement != previous) second else failure(SAME_PARENT)
    }

    /** Linux kill(pid, 0) tests existence without sending a signal. EPERM means it exists. */
    fun parentAlive(pid: Int): Boolean? {
        if (pid <= 1) return null
        return try {
            Os.kill(pid, 0)
            true
        } catch (error: ErrnoException) {
            when (error.errno) {
                OsConstants.ESRCH -> false
                OsConstants.EPERM -> true
                else -> null
            }
        } catch (_: SecurityException) {
            null
        }
    }

    /** No blind rebind: an unobservable PID is not proof of exit. Caller imposes a deadline. */
    suspend fun awaitParentExit(
        pid: Int,
        probe: (Int) -> Boolean? = ::parentAlive,
        intervalMs: Long = 250L,
    ): Boolean {
        while (true) {
            when (probe(pid)) {
                false -> return true
                null -> return false
                true -> delay(intervalMs)
            }
        }
    }
}
