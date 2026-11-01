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

package com.eltavine.duckdetector.features.zygisk.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskReport
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskSignal
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskSignalGroup
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskSignalSeverity
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskStage
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskAtexitObservation
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskAtexitState
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskRowIcon
import org.junit.Assert.assertEquals
import org.junit.Test

class ZygiskCardModelMapperTest {

    private val mapper = ZygiskCardModelMapper()

    @Test
    fun `fd trap positive maps to danger`() {
        val model = mapper.map(report(fdTrapDetected = true))
        assertEquals(DetectorStatus.danger(), model.status)
    }

    @Test
    fun `one direct native signal maps to danger`() {
        val model = mapper.map(report(nativeStrongHitCount = 1))
        assertEquals(DetectorStatus.danger(), model.status)
    }

    @Test
    fun `NeoZygisk TMP_PATH marker renders as danger signal`() {
        val model = mapper.map(
            report(
                nativeStrongHitCount = 1,
                signals = listOf(
                    ZygiskSignal(
                        id = "zygisk_trace_0",
                        label = "NeoZygisk environment marker",
                        value = "Danger",
                        group = ZygiskSignalGroup.RUNTIME,
                        severity = ZygiskSignalSeverity.DANGER,
                        detail = "Environment contains NeoZygisk marker: TMP_PATH=/data/adb/neozygisk.",
                        direct = true,
                        detailMonospace = true,
                    ),
                ),
            ),
        )

        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals("NeoZygisk environment marker", model.signalRows.single().label)
        assertEquals(DetectorStatus.danger(), model.signalRows.single().status)
        assertEquals(true, model.signalRows.single().detailMonospace)
    }

    @Test
    fun `one heuristic signal maps to warning`() {
        val model = mapper.map(report(heuristicHitCount = 1))
        assertEquals(DetectorStatus.warning(), model.status)
    }

    @Test
    fun `two heuristic signals escalate to danger`() {
        val model = mapper.map(report(heuristicHitCount = 2))
        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals("2 heuristic families converged", model.verdict)
        assertEquals(
            "Multiple heuristic families surfaced in the current process. Review the individual findings and benign causes; these observations do not establish Zygisk injection.",
            model.summary,
        )
        assertEquals(
            "Multiple heuristic families need review. Their convergence does not establish Zygisk injection.",
            model.impactItems.first().text,
        )
    }

    @Test
    fun `no hits with full coverage maps to all clear`() {
        val model = mapper.map(report())
        assertEquals(DetectorStatus.allClear(), model.status)
    }

    @Test
    fun `unavailable fd trap and native support maps to info`() {
        val model = mapper.map(
            report(
                fdTrapAvailable = false,
                nativeAvailable = false,
            ),
        )
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), model.status)
    }

    @Test
    fun `signal rows take their icon from their group`() {
        val model = mapper.map(
            report(
                signals = ZygiskSignalGroup.entries.mapIndexed { index, group ->
                    ZygiskSignal(
                        id = "zygisk_trace_$index",
                        label = group.name,
                        value = "Warning",
                        group = group,
                        severity = ZygiskSignalSeverity.WARNING,
                        detail = "detail",
                        direct = false,
                    )
                },
            ),
        )

        assertEquals(
            listOf(
                ZygiskRowIcon.CROSS_PROCESS,
                null,
                ZygiskRowIcon.LINKER,
                ZygiskRowIcon.MEMORY,
                ZygiskRowIcon.MEMORY,
                null,
                null,
            ),
            model.signalRows.map { it.icon },
        )
    }

    @Test
    fun `loading placeholders keep their labels and icons`() {
        val model = mapper.map(ZygiskReport.loading())

        assertEquals(
            listOf(
                "Cross-process FD trap" to ZygiskRowIcon.CROSS_PROCESS,
                "Native snapshot" to null,
                "Linker and namespace" to ZygiskRowIcon.LINKER,
                "Maps and smaps" to ZygiskRowIcon.MEMORY,
                "Threads and FDs" to null,
                "Solist, atexit, heap" to ZygiskRowIcon.MEMORY,
                "Exit-handler table" to ZygiskRowIcon.LINKER,
            ),
            model.methodRows.map { it.label to it.icon },
        )
        assertEquals(
            listOf(
                "Cross-process" to ZygiskRowIcon.CROSS_PROCESS,
                "Runtime" to null,
                "Linker" to ZygiskRowIcon.LINKER,
                "Maps" to ZygiskRowIcon.MEMORY,
                "Heap" to ZygiskRowIcon.MEMORY,
                "Threads" to null,
                "FDs" to null,
            ),
            model.signalRows.map { it.label to it.icon },
        )
    }

    private fun report(
        fdTrapAvailable: Boolean = true,
        fdTrapDetected: Boolean = false,
        nativeAvailable: Boolean = true,
        nativeStrongHitCount: Int = 0,
        heuristicHitCount: Int = 0,
        signals: List<ZygiskSignal> = emptyList(),
    ): ZygiskReport {
        return ZygiskReport(
            stage = ZygiskStage.READY,
            fdTrapAvailable = fdTrapAvailable,
            fdTrapDetected = fdTrapDetected,
            nativeAvailable = nativeAvailable,
            heapAvailable = true,
            nativeStrongHitCount = nativeStrongHitCount,
            heuristicHitCount = heuristicHitCount,
            tracerPid = 0,
            signals = signals,
            methods = emptyList(),
            references = ZygiskReport.defaultReferences(),
            atexitTable = ZygiskAtexitObservation(state = ZygiskAtexitState.COLLECTED),
        )
    }
}
