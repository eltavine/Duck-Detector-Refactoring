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

/** Collection outcomes only; the SELinux feature classifies the lookup counts. */
public enum class SelinuxAvcLookupState {
    NOT_COLLECTED, COLLECTED, TIMING_ONLY, PERMISSION_LIMITED, UNSUPPORTED, UNAVAILABLE, INCONCLUSIVE,
}

public enum class SelinuxAvcLookupStep {
    CARRIER, ENFORCE, OPEN, CONTROLS, TIMING, AFFINITY, CPU_MAP, STATS, COUNTING, IDENTITY, FINISHED,
}

/** The payload whose write did not fail with EINVAL. */
public enum class SelinuxAvcLookupPayload {
    NONE, A, B,
}

public enum class SelinuxAvcLookupChildEnd {
    EXITED, NOT_STARTED, SETUP_FAILED, SIGNALED, SECCOMP_TRAPPED, TIMED_OUT, NOT_REAPED, WAIT_FAILED,
}

/**
 * Per-batch deltas of the pinned CPU's AVC lookup counter and paired write timing, captured during
 * preload. The counter is shared by every task on that CPU; it is not a trace of this child's calls.
 */
public data class SelinuxAvcLookupSnapshot(
    val state: SelinuxAvcLookupState = SelinuxAvcLookupState.NOT_COLLECTED,
    val step: SelinuxAvcLookupStep? = null,
    val errno: Int = 0,
    val unexpectedPayload: SelinuxAvcLookupPayload = SelinuxAvcLookupPayload.NONE,
    /** What the unexpected write returned: -1 for a failure (errno in [errno]), else a byte count. */
    val unexpectedReturned: Long = 0,
    val identityChanged: Boolean = false,
    val cpu: Int = -1,
    val cpuRow: Int = -1,
    val cpuRows: Int = 0,
    val possibleCpus: Int = 0,
    val pairs: Int = 0,
    val rounds: Int = 0,
    val writesPerBatch: Int = 0,
    val batchesA: List<Long> = emptyList(),
    val batchesB: List<Long> = emptyList(),
    val medianANs: Long = 0,
    val medianBNs: Long = 0,
    val medianDeltaNs: Long = 0,
    val childEnd: SelinuxAvcLookupChildEnd? = null,
    val childExitStatus: Int = 0,
    val childSignal: Int = 0,
    val childErrno: Int = 0,
    val failureReason: String? = null,
) {
    public companion object {
        /** Must match kRounds, kWrites and kPairs in avc_lookup_probe.h. */
        public const val ROUNDS: Int = 4
        public const val WRITES_PER_BATCH: Int = 4096
        public const val PAIRS: Int = 128
    }
}
