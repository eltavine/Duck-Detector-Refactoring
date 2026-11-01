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
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
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
        assertEquals("Newer than audited", row(HeapResidueRelease.NEWER)?.value)
        assertEquals("Pre-release build", row(HeapResidueRelease.PRERELEASE)?.value)
        assertNull(row(HeapResidueRelease.UNKNOWN))
    }
    @Test fun overviewAndMethodsKeepNegativeHistoricalCoverageInformational() {
        val model = HeapResidueCardModelMapper().map(HeapResidueReport(HeapResidueStage.READY,
            HeapResidueOutcome.NOT_OBSERVED, candidateCount = 12, bytesRead = 1024))
        assertEquals(4, model.headerFacts.size)
        assertEquals("12", model.headerFacts.single { it.label == "Arguments" }.value)
        assertEquals("Unknown", model.headerFacts.single { it.label == "Coverage" }.value)
        assertTrue((model.headerFacts + model.methodRows + model.impactRows).all {
            it.status == DetectorStatus.info(InfoKind.SUPPORT)
        })
        assertEquals(4, model.toDetectorReport().quickFacts.size)
    }
    @Test fun unavailableAndUnsupportedDoNotShowMeasuredZeroesInOverview() {
        val mapper = HeapResidueCardModelMapper()
        val failed = mapper.map(HeapResidueReport.failed("dump failed"))
        assertEquals("Unavailable", failed.headerFacts.single { it.label == "Traces" }.value)
        assertTrue(failed.headerFacts.filter { it.label != "Coverage" }.all { it.status == DetectorStatus.info(InfoKind.ERROR) })
        assertEquals(DetectorStatus.info(InfoKind.ERROR), failed.methodRows.first().status)
        val unsupported = mapper.map(HeapResidueReport(HeapResidueStage.READY, HeapResidueOutcome.UNSUPPORTED))
        assertEquals("Unsupported", unsupported.methodRows.first().value)
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), unsupported.methodRows.first().status)
    }

    @Test fun inconclusiveMatchingDoesNotReadAsZeroTargetTraces() {
        val model = HeapResidueCardModelMapper().map(HeapResidueReport(HeapResidueStage.READY,
            HeapResidueOutcome.INCONCLUSIVE, candidateCount = 0, bytesRead = 1024))
        assertEquals("Inconclusive", model.headerFacts.single { it.label == "Traces" }.value)
        assertEquals("Inconclusive", model.methodRows.single { it.label == "Startup argument matching" }.value)
        assertEquals("Snapshot collected", model.methodRows.single { it.label == "Isolated ART heap capture" }.value)
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), model.status)
    }
    @Test fun unattemptedAndFailedReportsDoNotClaimANegativeSnapshot() {
        val mapper = HeapResidueCardModelMapper()
        val pending = mapper.map(HeapResidueReport(HeapResidueStage.READY))
        assertEquals("Not evaluated", pending.verdict)
        assertTrue(pending.summary.contains("No snapshot evaluation"))
        val failed = mapper.map(HeapResidueReport(HeapResidueStage.FAILED, errorMessage = "Capture failed"))
        assertEquals("Probe unavailable", failed.verdict)
        assertEquals("Capture failed", failed.summary)
    }
}
