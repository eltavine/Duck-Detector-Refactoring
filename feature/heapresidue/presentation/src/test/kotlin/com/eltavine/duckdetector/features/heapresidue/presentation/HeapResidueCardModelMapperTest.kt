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

package com.eltavine.duckdetector.features.heapresidue.presentation

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.features.heapresidue.domain.*
import org.junit.Assert.*
import org.junit.Test

class HeapResidueCardModelMapperTest {
    @Test fun negativeSnapshotExplainsUnknownCoverage() {
        val model = HeapResidueCardModelMapper().map(HeapResidueReport(HeapResidueStage.READY, HeapResidueOutcome.NOT_OBSERVED))
        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertEquals("No target trace observed", model.verdict)
        assertTrue(model.summary.contains("history is incomplete"))
    }
    @Test fun findingDoesNotClaimInstallationOrCompromise() {
        val model = HeapResidueCardModelMapper().map(HeapResidueReport(HeapResidueStage.READY,
            HeapResidueOutcome.OBSERVED, listOf(HeapResidueSignal("com.target.app", setOf(HeapResidueArgument.NICE_NAME)))))
        assertEquals(DetectionSeverity.WARNING, model.status.severity)
        assertTrue(model.summary.contains("does not prove current installation"))
        assertEquals("Argument trace", model.signalRows.single().value)
    }
    @Test fun failureAndUnsupportedRemainDistinct() {
        val mapper = HeapResidueCardModelMapper()
        assertEquals("Probe unavailable", mapper.map(HeapResidueReport.failed("IOException")).verdict)
        val unsupported = mapper.map(HeapResidueReport(HeapResidueStage.READY, HeapResidueOutcome.UNSUPPORTED))
        assertEquals("Unsupported", unsupported.verdict)
        assertTrue(unsupported.summary.contains("Android 12 to 17"))
    }
    @Test fun releaseRowSeparatesAuditedFromNewerReleases() {
        fun row(release: HeapResidueRelease) = HeapResidueCardModelMapper()
            .map(HeapResidueReport(HeapResidueStage.READY, HeapResidueOutcome.NOT_OBSERVED, release = release))
            .scanRows.firstOrNull { it.label == "Android release" }
        assertEquals("Audited baseline", row(HeapResidueRelease.AUDITED)?.value)
        assertEquals("Newer than audited", row(HeapResidueRelease.UNAUDITED)?.value)
        assertNull(row(HeapResidueRelease.UNKNOWN))
    }
}
