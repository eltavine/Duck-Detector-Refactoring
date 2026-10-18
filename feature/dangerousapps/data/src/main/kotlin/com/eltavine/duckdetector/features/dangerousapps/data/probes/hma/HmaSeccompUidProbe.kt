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

package com.eltavine.duckdetector.features.dangerousapps.data.probes.hma

import android.os.Process
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaBehaviorCheck
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckKind
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckState
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaSeccompUidEvidence
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaSeccompUidObservation
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaSeccompUidPolicy
import kotlinx.coroutines.ensureActive
import kotlin.coroutines.coroutineContext

/**
 * Probes whether a seccomp filter already answers getpriority(PRIO_USER, *) for the caller.
 *
 * A disposable child installs a SECCOMP_RET_USER_NOTIF filter for getpriority(PRIO_USER, *), then
 * forks a query child that asks for every UID in the caller's app range. EBUSY means an existing
 * filter in this task already owns a listener. When the
 * listener installs, every query whose notification arrives was not answered by another filter;
 * missing notifications after a completed range indicate higher-priority suppression. The
 * filter never leaves the disposable child, so the app process keeps its original seccomp stack.
 */
internal class HmaSeccompUidProbe(
    private val bridge: HmaSeccompUidBridge = HmaSeccompUidBridge(),
) {
    suspend fun run(): HmaBehaviorCheck {
        coroutineContext.ensureActive()
        val self = Process.myUid()
        val base = self / HmaPlatformCalls.PER_USER_RANGE * HmaPlatformCalls.PER_USER_RANGE
        if (self - base !in 10000..19999) {
            return HmaBehaviorCheck(
                HmaCheckKind.SECCOMP_UID_FILTER,
                HmaCheckState.UNSUPPORTED,
                "Caller is outside the ordinary application UID range.",
            )
        }
        val snapshot = bridge.probe(base + 10000, base + 19999)
        coroutineContext.ensureActive()
        if (snapshot.failure.isNotEmpty()) {
            return HmaBehaviorCheck(
                HmaCheckKind.SECCOMP_UID_FILTER,
                HmaCheckState.UNAVAILABLE,
                "Native seccomp listener probe unavailable: ${snapshot.failure}",
            )
        }
        return HmaSeccompUidPolicy.evaluate(snapshot.toObservation())
    }
}

internal fun UidSeccompSnapshot.toObservation(): HmaSeccompUidObservation {
    val evidence = when {
        installStatus == HmaSeccompUidBridge.FOREIGN_LISTENER -> HmaSeccompUidEvidence.FOREIGN_LISTENER
        installStatus == HmaSeccompUidBridge.INSTALL_TRAPPED -> HmaSeccompUidEvidence.TRAPPED_INSTALL
        installStatus == HmaSeccompUidBridge.UNSUPPORTED -> HmaSeccompUidEvidence.UNSUPPORTED
        installStatus == HmaSeccompUidBridge.RESTRICTED -> HmaSeccompUidEvidence.RESTRICTED
        installStatus != HmaSeccompUidBridge.INSTALLED ->
            if (installError == 110) HmaSeccompUidEvidence.INCOMPLETE else HmaSeccompUidEvidence.FAILED
        queryOutcome == HmaSeccompUidBridge.QUERY_TRAPPED -> HmaSeccompUidEvidence.TRAPPED_QUERY
        queryOutcome != HmaSeccompUidBridge.QUERY_COMPLETE -> HmaSeccompUidEvidence.INCOMPLETE
        notified < queried -> HmaSeccompUidEvidence.SUPPRESSED_QUERIES
        else -> HmaSeccompUidEvidence.NONE
    }
    val detail = when (evidence) {
        HmaSeccompUidEvidence.FOREIGN_LISTENER ->
            "seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER) returned EBUSY (errno $installError)."
        HmaSeccompUidEvidence.TRAPPED_INSTALL ->
            "the probe child was terminated by a seccomp trap before reporting a listener " +
                "result (signal $installError)."
        HmaSeccompUidEvidence.UNSUPPORTED ->
            "the listener install returned errno $installError (${errnoName(installError)})."
        HmaSeccompUidEvidence.RESTRICTED ->
            "the listener install was refused with errno $installError (${errnoName(installError)})."
        HmaSeccompUidEvidence.FAILED ->
            "the native child ended without a listener result (errno/signal $installError)."
        HmaSeccompUidEvidence.TRAPPED_QUERY ->
            "SIGSYS identified getpriority(PRIO_USER) on the query ABI (signal $queryError); " +
                "$notified notification(s) arrived before it."
        HmaSeccompUidEvidence.INCOMPLETE ->
            "query outcome=${queryOutcomeLabel(queryOutcome)}, error=$queryError, notifications=$notified, coordinator error=$installError."
        HmaSeccompUidEvidence.SUPPRESSED_QUERIES ->
            "${queried - notified} of $queried queries produced no notification."
        HmaSeccompUidEvidence.NONE ->
            "$notified of $queried queries produced a notification."
    }
    return HmaSeccompUidObservation(
        evidence = evidence,
        kernelMajor = kernelMajor,
        kernelMinor = kernelMinor,
        queried = queried,
        notified = notified,
        firstSuppressed = firstSuppressed,
        lastSuppressed = lastSuppressed,
        selfNotified = selfNotified,
        detail = detail,
    )
}

private fun errnoName(value: Int): String = when (value) {
    1 -> "EPERM"
    13 -> "EACCES"
    16 -> "EBUSY"
    22 -> "EINVAL"
    38 -> "ENOSYS"
    110 -> "ETIMEDOUT"
    else -> "errno"
}

private fun queryOutcomeLabel(value: Int): String = when (value) {
    HmaSeccompUidBridge.QUERY_COMPLETE -> "completed"
    HmaSeccompUidBridge.QUERY_TRAPPED -> "trapped"
    HmaSeccompUidBridge.QUERY_SIGNALED -> "signaled"
    HmaSeccompUidBridge.QUERY_TIMEOUT -> "timeout"
    HmaSeccompUidBridge.QUERY_FAILURE -> "failure"
    HmaSeccompUidBridge.QUERY_NOT_RUN -> "not run"
    else -> "unknown"
}
