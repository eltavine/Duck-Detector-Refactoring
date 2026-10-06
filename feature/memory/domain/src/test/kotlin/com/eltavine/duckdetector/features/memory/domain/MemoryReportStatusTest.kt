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

package com.eltavine.duckdetector.features.memory.domain

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import org.junit.Assert.assertEquals
import org.junit.Test

class MemoryReportStatusTest {

    private fun readyWith(severity: MemoryFindingSeverity): MemoryReport = MemoryReport.loading().copy(
        stage = MemoryStage.READY,
        findings = listOf(
            MemoryFinding(
                id = "memory_0",
                section = MemoryFindingSection.MAPS,
                category = "SMAPS",
                label = "Privately copied system code matches its file",
                detail = "/system/lib64/libc.so: 1 privately copied executable page(s) match the file byte for byte",
                severity = severity,
                detailMonospace = true,
            ),
        ),
    )

    @Test
    fun `a low finding alone leaves the memory status clear`() {
        assertEquals(
            DetectionSeverity.ALL_CLEAR,
            readyWith(MemoryFindingSeverity.LOW).toDetectorStatus().severity,
        )
    }

    @Test
    fun `a medium finding asks for review`() {
        assertEquals(
            DetectionSeverity.WARNING,
            readyWith(MemoryFindingSeverity.MEDIUM).toDetectorStatus().severity,
        )
    }
}
