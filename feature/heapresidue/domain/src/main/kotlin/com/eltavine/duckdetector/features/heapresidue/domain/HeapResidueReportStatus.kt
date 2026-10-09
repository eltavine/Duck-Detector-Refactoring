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

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind

/** Even a complete dump has unknown historical coverage; a negative scan is never all-clear. */
fun HeapResidueReport.toDetectorStatus(): DetectorStatus = when {
    stage == HeapResidueStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
    stage == HeapResidueStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
    outcome == HeapResidueOutcome.OBSERVED && signals.isNotEmpty() -> DetectorStatus.warning()
    outcome == HeapResidueOutcome.UNAVAILABLE -> DetectorStatus.info(InfoKind.ERROR)
    else -> DetectorStatus.info(InfoKind.SUPPORT)
}

/** Snapshot completion and candidate visibility are required even for the narrow not-observed state. */
fun heapResidueOutcome(complete: Boolean, candidates: Int, signals: List<HeapResidueSignal>): HeapResidueOutcome = when {
    !complete -> HeapResidueOutcome.UNAVAILABLE
    signals.isNotEmpty() -> HeapResidueOutcome.OBSERVED
    candidates == 0 -> HeapResidueOutcome.INCONCLUSIVE
    else -> HeapResidueOutcome.NOT_OBSERVED
}
