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

import com.eltavine.duckdetector.core.native.NativeSnapshotCollector

public data class SelinuxProcAttrCurrentResult(
    val label: String,
    val targetContext: String,
    val outcomeClass: String,
    val rawMessage: String,
) {
    /** Legacy error-only results lack conversion controls and cannot establish a finding. */
    public fun detected(): Boolean = outcomeClass == OUTCOME_CONTEXT_RECOGNIZED

    public companion object {
        public const val OUTCOME_SUCCESS: String = "SUCCESS"
        public const val OUTCOME_NORMAL_EINVAL: String = "NORMAL_EINVAL"
        public const val OUTCOME_DETECTED_NON_EINVAL: String = "DETECTED_NON_EINVAL"
        public const val OUTCOME_DETECTED_SECURITY_EXCEPTION: String = "DETECTED_SECURITY_EXCEPTION"
        public const val OUTCOME_CONTEXT_RECOGNIZED: String = "CONTEXT_RECOGNIZED"
        public const val OUTCOME_CONTROLS_PASSED: String = "CONTROLS_PASSED"
        public const val OUTCOME_PERMISSION_LIMITED: String = "PERMISSION_LIMITED"
        public const val OUTCOME_UNSUPPORTED: String = "UNSUPPORTED"
        public const val OUTCOME_UNAVAILABLE: String = "UNAVAILABLE"
        public const val OUTCOME_INCONCLUSIVE: String = "INCONCLUSIVE"
        public const val CONTROL_LABEL: String = "Controls"

        /** Candidate records after the controls record; must match kTargets in proc_attr_probe.h. */
        public const val TARGET_COUNT: Int = 9
    }
}

internal class SelinuxProcAttrCurrentProbe(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
) {
    /** Collects controls and repeated writes in a bounded child, without changing the carrier identity. */
    fun inspect(): List<SelinuxProcAttrCurrentResult> = collector.collect(
        readPayload = ::nativeCollectProcAttr,
        parse = SelinuxProcAttrCurrentNativePayload::decode,
        unavailable = { failure ->
            listOf(
                SelinuxProcAttrCurrentResult(
                    label = SelinuxProcAttrCurrentResult.CONTROL_LABEL,
                    targetContext = "",
                    outcomeClass = SelinuxProcAttrCurrentResult.OUTCOME_UNAVAILABLE,
                    rawMessage = failure.explain("Controlled context-write probe unavailable"),
                ),
            )
        },
    )

    private external fun nativeCollectProcAttr(): String
}
