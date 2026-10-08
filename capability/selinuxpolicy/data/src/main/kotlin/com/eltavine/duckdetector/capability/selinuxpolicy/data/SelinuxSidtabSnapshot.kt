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

/** Linux UAPI errno-base.h, used by bionic on all four supported ABIs; these are wire codes.
 * android-15.0.0_r1 libc/kernel/uapi/asm-generic/errno-base.h defines 13 and 22.
 * Keep parsing independent of android.system.OsConstants initialization (including JVM hosts).
 */
public enum class SelinuxSidtabErrno(public val code: Int) {
    SUCCESS(0), PERMISSION_DENIED(13), INVALID_ARGUMENT(22),
}

/** Collection outcomes only; the SELinux feature interprets the counter differences. */
public enum class SelinuxSidtabCollection {
    NOT_COLLECTED, COMPLETE, UNSUPPORTED, PERMISSION_LIMITED, UNAVAILABLE, INCONCLUSIVE,
}

public enum class SelinuxSidtabChildEnd {
    EXITED, NOT_STARTED, SETUP_FAILED, SIGNALED, SECCOMP_TRAPPED, TIMED_OUT, NOT_REAPED, WAIT_FAILED,
}

public enum class SelinuxSidtabStep {
    SETUP, CARRIER, CONTROLS, CONTEXT, ATTR_CURRENT, REPEAT, FINISHED,
}

public data class SelinuxSidtabSample(
    val context: String,
    val contextErrno: Int?,
    val attrErrno: Int?,
    val repeatErrno: Int?,
)

public data class SelinuxSidtabRound(
    val beforeControls: Long?,
    val before: Long?,
    val afterContext: Long?,
    val afterAttr: Long?,
    val afterRepeat: Long?,
    val idleEnd: Long?,
    val positiveErrno: Int?,
    val negativeErrno: Int?,
    val attrNegativeErrno: Int?,
    val samples: List<SelinuxSidtabSample>,
)

/** A bounded experiment captured during preload, not a new measurement on each UI refresh. */
public data class SelinuxSidtabSnapshot(
    val collection: SelinuxSidtabCollection = SelinuxSidtabCollection.NOT_COLLECTED,
    val attempted: Boolean = false,
    val step: SelinuxSidtabStep = SelinuxSidtabStep.SETUP,
    val errno: Int? = null,
    val completedRounds: Int = 0,
    val canonicalMismatch: Boolean = false,
    val identityChanged: Boolean = false,
    val uid: Int? = null,
    val pid: Int? = null,
    val capturedUptimeMs: Long? = null,
    val carrierContext: String? = null,
    val kernelRelease: String? = null,
    val childEnd: SelinuxSidtabChildEnd? = null,
    val signal: Int? = null,
    val rounds: List<SelinuxSidtabRound> = emptyList(),
    val failureReason: String? = null,
)
