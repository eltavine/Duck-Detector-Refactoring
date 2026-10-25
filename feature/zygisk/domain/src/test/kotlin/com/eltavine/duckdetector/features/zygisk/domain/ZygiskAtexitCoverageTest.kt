// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.features.zygisk.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import org.junit.Assert.*
import org.junit.Test

class ZygiskAtexitCoverageTest {
    private fun report(state: ZygiskAtexitState) = ZygiskReport(
        stage = ZygiskStage.READY, fdTrapAvailable = true, fdTrapDetected = false,
        nativeAvailable = true, heapAvailable = true, nativeStrongHitCount = 0,
        heuristicHitCount = 0, tracerPid = 0, signals = emptyList(),
        methods = emptyList(), references = emptyList(),
        atexitTable = ZygiskAtexitObservation(state = state),
    )

    @Test fun onlyEvaluatedTableAllowsAnAllClear() {
        assertEquals(DetectorStatus.allClear(), report(ZygiskAtexitState.COLLECTED).toDetectorStatus())
        ZygiskAtexitState.entries.filter { it != ZygiskAtexitState.COLLECTED }.forEach { state ->
            val report = report(state)
            assertFalse(state.name, report.fullyClean)
            assertTrue(state.name, report.supportOnly)
        }
    }

    @Test fun incompleteCoveragePreservesObservedEvidence() {
        val warning = report(ZygiskAtexitState.PARTIAL).copy(heuristicHitCount = 1)
        assertEquals(DetectorStatus.warning(), warning.toDetectorStatus())
        assertFalse(warning.supportOnly)
    }

    @Test fun tableEvidenceCannotBeClearedByAnEmptyAggregateCounter() {
        listOf(ZygiskAtexitState.COLLECTED, ZygiskAtexitState.PARTIAL).forEach { state ->
            val observed = report(state).copy(atexitTable = ZygiskAtexitObservation(
                state = state, entries = 10, anonymousCallbacks = 1,
            ))
            assertFalse(observed.fullyClean)
            assertFalse(observed.supportOnly)
            assertEquals(DetectorStatus.warning(), observed.toDetectorStatus())
        }
    }
}
