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

/**
 * What the seccomp listener probe observed, before it is interpreted as an HMA check state.
 *
 * The probe installs a SECCOMP_RET_USER_NOTIF filter for getpriority(PRIO_USER, *) with
 * SECCOMP_FILTER_FLAG_NEW_LISTENER in a disposable child. The kernel's seccomp action order makes
 * ERRNO and TRAP outrank USER_NOTIF, so a foreign filter can suppress the notification without
 * removing the query.
 */
enum class HmaSeccompUidEvidence {
    /** The listener was installed and every query in scope produced a notification. */
    NONE,

    /** NEW_LISTENER returned EBUSY: an existing filter in this task already owns a listener. */
    FOREIGN_LISTENER,

    /** The listener was installed, but a foreign filter answered part of the query range first. */
    SUPPRESSED_QUERIES,

    /** A getpriority(PRIO_USER) query was terminated by a seccomp trap. */
    TRAPPED_QUERY,

    /** The coordinator ended by SIGSYS without a complete report or syscall attribution. */
    TRAPPED_INSTALL,

    /** The kernel lacks the documented NEW_LISTENER behavior or rejected the probe program. */
    UNSUPPORTED,

    /** The process policy refused the listener install or the probe UID is out of scope. */
    RESTRICTED,

    /** The native probe ended without a listener or query result. */
    FAILED,

    /** The listener was installed but the query phase did not complete. */
    INCOMPLETE,
}

data class HmaSeccompUidObservation(
    val evidence: HmaSeccompUidEvidence,
    val kernelMajor: Int,
    val kernelMinor: Int,
    val queried: Int,
    val notified: Int,
    val firstSuppressed: Int,
    val lastSuppressed: Int,
    val selfNotified: Boolean,
    val detail: String = "",
)

/**
 * Turns the probe's raw observation into a warning-level behavior check.
 *
 * EBUSY is interpreted only when the kernel is at least 5.0: Linux v5.0 introduced
 * SECCOMP_RET_USER_NOTIF and the NEW_LISTENER flag. Its duplicate-listener path returns EBUSY
 * when both the new filter and an ancestor carry listeners; another filter may also synthesize errno. Older
 * kernels reject the flag with EINVAL, so an EBUSY there cannot be attributed to a listener.
 */
object HmaSeccompUidPolicy {
    fun evaluate(observation: HmaSeccompUidObservation): HmaBehaviorCheck {
        val kernel = "Kernel ${observation.kernelMajor}.${observation.kernelMinor}."
        val state = when (observation.evidence) {
            HmaSeccompUidEvidence.NONE ->
                if (observation.queried > 0 && observation.notified == observation.queried && observation.selfNotified)
                    HmaCheckState.CONSISTENT else HmaCheckState.INCONCLUSIVE
            HmaSeccompUidEvidence.FOREIGN_LISTENER ->
                if (observation.kernelMajor >= 5) HmaCheckState.INCONSISTENT else HmaCheckState.INCONCLUSIVE
            HmaSeccompUidEvidence.SUPPRESSED_QUERIES ->
                if (observation.notified >= 0 && observation.queried > observation.notified &&
                    observation.firstSuppressed >= 0 && observation.lastSuppressed >= observation.firstSuppressed)
                    HmaCheckState.INCONSISTENT else HmaCheckState.INCONCLUSIVE
            HmaSeccompUidEvidence.TRAPPED_QUERY -> HmaCheckState.INCONSISTENT
            HmaSeccompUidEvidence.TRAPPED_INSTALL -> HmaCheckState.PERMISSION_LIMITED
            HmaSeccompUidEvidence.UNSUPPORTED -> HmaCheckState.UNSUPPORTED
            HmaSeccompUidEvidence.RESTRICTED -> HmaCheckState.PERMISSION_LIMITED
            HmaSeccompUidEvidence.FAILED -> HmaCheckState.UNAVAILABLE
            HmaSeccompUidEvidence.INCOMPLETE -> HmaCheckState.INCONCLUSIVE
        }
        val detail = when (observation.evidence) {
            HmaSeccompUidEvidence.NONE -> if (state != HmaCheckState.CONSISTENT) {
                "The completed notification claim lacks matching counts or a caller control " +
                    "(queried=${observation.queried}, notified=${observation.notified}, self=${observation.selfNotified}). $kernel"
            } else
                "A NEW_LISTENER filter was installed and all ${observation.queried} " +
                    "getpriority(PRIO_USER) queries for the caller's app UID range produced notifications; " +
                    "no higher-priority suppression was observed. $kernel " +
                    "The probe covers seccomp filters in this process."

            HmaSeccompUidEvidence.FOREIGN_LISTENER ->
                if (observation.kernelMajor >= 5) {
                    "seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER) returned EBUSY. " +
                        "The ACK duplicate-listener path returns EBUSY when an existing filter " +
                        "already carries a listener; an inherited policy can also synthesize errno. $kernel " +
                        "This is seccomp interference evidence; it does not identify the module."
                } else {
                    "seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER) returned EBUSY, but $kernel " +
                        "predates the documented Linux 5.0 user-notification semantics, so the errno " +
                        "is not interpreted as listener evidence."
                }

            HmaSeccompUidEvidence.SUPPRESSED_QUERIES -> {
                val suppressed = (observation.queried - observation.notified).coerceAtLeast(0)
                "A NEW_LISTENER filter was installed, but $suppressed of " +
                    "${observation.queried} getpriority(PRIO_USER) queries produced no notification " +
                    "(first suppressed UID=${observation.firstSuppressed}, " +
                    "last=${observation.lastSuppressed}). A foreign filter answered them with a lower " +
                    "action than USER_NOTIF. $kernel " +
                    "This is seccomp interference evidence; it does not identify the module."
            }

            HmaSeccompUidEvidence.TRAPPED_QUERY ->
                "A getpriority(PRIO_USER) query was terminated by a seccomp trap after the " +
                    "NEW_LISTENER filter was installed; a non-platform filter or an OEM policy refused " +
                    "the call. $kernel This is seccomp interference evidence; it does not identify the module."

            HmaSeccompUidEvidence.TRAPPED_INSTALL ->
                "The disposable probe was refused by SIGSYS before reporting its result. The faulting " +
                    "syscall is unknown, so this is permission-limited coverage. $kernel"

            HmaSeccompUidEvidence.UNSUPPORTED ->
                "The listener probe did not install: ${observation.detail} $kernel " +
                    "The running kernel does not expose the documented NEW_LISTENER behavior " +
                    "(Linux < 5.0) or rejected the probe program."

            HmaSeccompUidEvidence.RESTRICTED ->
                "The listener probe was permission limited: ${observation.detail} $kernel"

            HmaSeccompUidEvidence.FAILED ->
                "The listener probe failed: ${observation.detail} $kernel"

            HmaSeccompUidEvidence.INCOMPLETE ->
                "The listener filter was installed, but the query phase did not complete " +
                    "(${observation.detail}); query suppression cannot be established. $kernel"
        }
        return HmaBehaviorCheck(HmaCheckKind.SECCOMP_UID_FILTER, state, detail)
    }
}
