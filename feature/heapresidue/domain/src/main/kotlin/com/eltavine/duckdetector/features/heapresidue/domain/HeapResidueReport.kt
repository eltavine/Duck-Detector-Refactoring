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

package com.eltavine.duckdetector.features.heapresidue.domain

enum class HeapResidueStage { LOADING, READY, FAILED }
enum class HeapResidueOutcome { NOT_EVALUATED, UNSUPPORTED, UNAVAILABLE, INCONCLUSIVE, NOT_OBSERVED, OBSERVED }
enum class HeapResidueArgument { PACKAGE_NAME, NICE_NAME, APP_DATA_DIR }
enum class HeapResidueProbeFailure { BINDING, HIDDEN_API, DUMP, TIMEOUT, MALFORMED_HPROF, STREAM }
enum class HeapResidueRetention { UNKNOWN, DISABLED, SAVED, TOO_LARGE, FAILED }

data class HeapResidueSignal(val packageName: String, val arguments: Set<HeapResidueArgument>)

/** No field represents an installed-app inventory or complete startup history. */
data class HeapResidueReport(
    val stage: HeapResidueStage,
    val outcome: HeapResidueOutcome = HeapResidueOutcome.NOT_EVALUATED,
    val signals: List<HeapResidueSignal> = emptyList(),
    val bytesRead: Long = 0,
    val candidateCount: Int = 0,
    val captureAgeMillis: Long? = null,
    val dumpDurationMillis: Long? = null,
    val gcCountBefore: Long? = null,
    val retention: HeapResidueRetention = HeapResidueRetention.UNKNOWN,
    val probeFailure: HeapResidueProbeFailure? = null,
    val errorMessage: String? = null,
) {
    companion object {
        fun loading() = HeapResidueReport(HeapResidueStage.LOADING)
        fun failed(message: String) = HeapResidueReport(
            stage = HeapResidueStage.FAILED,
            outcome = HeapResidueOutcome.UNAVAILABLE,
            errorMessage = message,
        )
    }
}
