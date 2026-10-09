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

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import org.junit.Assert.assertEquals
import org.junit.Test

class HeapResidueReportStatusTest {
    @Test fun everyNegativeOutcomeRemainsInformational() {
        HeapResidueOutcome.entries.forEach { outcome ->
            assertEquals(DetectionSeverity.INFO, HeapResidueReport(HeapResidueStage.READY, outcome).toDetectorStatus().severity)
        }
    }
    @Test fun onlyObservedEvidenceWarns() {
        val signal = HeapResidueSignal("com.target.app", setOf(HeapResidueArgument.PACKAGE_NAME))
        assertEquals(DetectionSeverity.WARNING, HeapResidueReport(HeapResidueStage.READY,
            HeapResidueOutcome.OBSERVED, listOf(signal)).toDetectorStatus().severity)
        assertEquals(DetectionSeverity.INFO, HeapResidueReport(HeapResidueStage.FAILED,
            HeapResidueOutcome.OBSERVED, listOf(signal)).toDetectorStatus().severity)
        assertEquals(DetectionSeverity.INFO, HeapResidueReport.loading().toDetectorStatus().severity)
    }
    @Test fun snapshotReductionRequiresCompletionAndDistinguishesNoCandidates() {
        val signal = HeapResidueSignal("com.target.app", setOf(HeapResidueArgument.PACKAGE_NAME))
        assertEquals(HeapResidueOutcome.UNAVAILABLE, heapResidueOutcome(false, 1, listOf(signal)))
        assertEquals(HeapResidueOutcome.OBSERVED, heapResidueOutcome(true, 1, listOf(signal)))
        assertEquals(HeapResidueOutcome.INCONCLUSIVE, heapResidueOutcome(true, 0, emptyList()))
        assertEquals(HeapResidueOutcome.NOT_OBSERVED, heapResidueOutcome(true, 1, emptyList()))
    }

}
