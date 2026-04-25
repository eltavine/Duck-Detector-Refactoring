/*
 * Copyright 2026 Duck Apps Contributor
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

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskReport
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskStage
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
    fun `one heuristic signal maps to warning`() {
        val model = mapper.map(report(heuristicHitCount = 1))
        assertEquals(DetectorStatus.warning(), model.status)
    }

    @Test
    fun `two heuristic signals escalate to danger`() {
        val model = mapper.map(report(heuristicHitCount = 2))
        assertEquals(DetectorStatus.danger(), model.status)
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

    private fun report(
        fdTrapAvailable: Boolean = true,
        fdTrapDetected: Boolean = false,
        nativeAvailable: Boolean = true,
        nativeStrongHitCount: Int = 0,
        heuristicHitCount: Int = 0,
    ): ZygiskReport {
        return ZygiskReport(
            stage = ZygiskStage.READY,
            fdTrapAvailable = fdTrapAvailable,
            fdTrapDetected = fdTrapDetected,
            nativeAvailable = nativeAvailable,
            heapAvailable = true,
            seccompSupported = true,
            nativeStrongHitCount = nativeStrongHitCount,
            heuristicHitCount = heuristicHitCount,
            tracerPid = 0,
            signals = emptyList(),
            methods = emptyList(),
            references = ZygiskReport.defaultReferences(),
        )
    }
}
