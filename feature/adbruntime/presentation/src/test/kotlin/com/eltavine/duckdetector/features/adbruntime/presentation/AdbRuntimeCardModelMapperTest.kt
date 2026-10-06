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

package com.eltavine.duckdetector.features.adbruntime.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.core.report.ReportBlock
import com.eltavine.duckdetector.features.adbruntime.domain.AdbMdnsServiceKind
import com.eltavine.duckdetector.features.adbruntime.domain.AdbMdnsSnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProbeState
import com.eltavine.duckdetector.features.adbruntime.domain.AdbPropertySnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProtocolResponseKind
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProtocolSnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeReport
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeSample
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeStage
import com.eltavine.duckdetector.features.adbruntime.domain.UsbRuntimeSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AdbRuntimeCardModelMapperTest {
    private val mapper = AdbRuntimeCardModelMapper()

    @Test
    fun unprobedScanReadsAsNotEvaluated() {
        val model = mapper.map(
            AdbRuntimeReport(
                stage = AdbRuntimeStage.READY,
                platformApiLevel = 36,
                samples = emptyList(),
                mdnsSamples = listOf(AdbMdnsSnapshot(AdbProbeState.UNAVAILABLE)),
                probed = false,
            ),
        )

        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), model.status)
        assertEquals("Not evaluated", model.verdict)
    }

    @Test
    fun protocolContradictionBecomesDangerRowAndExportBlock() {
        val sample = AdbRuntimeSample(
            usbDebuggingEnabled = true,
            debuggingFeaturesRestricted = false,
            properties = AdbPropertySnapshot(
                testHarnessMode = "0",
                initAdbdState = "stopped",
            ),
            usb = UsbRuntimeSnapshot(
                state = AdbProbeState.OBSERVED,
                configured = true,
                functions = setOf("adb"),
            ),
        )
        val mdns = AdbMdnsSnapshot(
            state = AdbProbeState.OBSERVED,
            serviceKind = AdbMdnsServiceKind.TLS_CONNECT,
            address = "192.0.2.5",
            port = 37123,
            protocol = AdbProtocolSnapshot(
                state = AdbProbeState.OBSERVED,
                responseKind = AdbProtocolResponseKind.START_TLS,
            ),
        )
        val model = mapper.map(
            AdbRuntimeReport(
                stage = AdbRuntimeStage.READY,
                platformApiLevel = 36,
                samples = listOf(sample, sample),
                mdnsSamples = listOf(mdns, mdns),
                probed = true,
            ),
        )
        val export = model.toDetectorReport()

        assertEquals(DetectorStatus.danger(), model.status)
        val finding = model.signalRows.single()
        assertEquals(DetectorStatus.danger(), finding.status)
        assertTrue(finding.detail.orEmpty().contains("192.0.2.5:37123"))
        assertTrue(model.scanRows.any { it.detail?.contains("protocol=ADB STLS request") == true })
        val rows = export.blocks
            .filterIsInstance<ReportBlock.Rows>()
            .single { it.title == "Inconsistencies" }
            .rows
        assertTrue(rows.isNotEmpty())
    }
}
