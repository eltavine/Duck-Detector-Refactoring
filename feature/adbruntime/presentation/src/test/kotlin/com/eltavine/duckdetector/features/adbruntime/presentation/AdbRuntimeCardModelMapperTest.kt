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
import com.eltavine.duckdetector.features.adbruntime.domain.AdbInitSocketSnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbJdwpSocketSnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbMdnsServiceKind
import com.eltavine.duckdetector.features.adbruntime.domain.AdbMdnsSnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProbeState
import com.eltavine.duckdetector.features.adbruntime.domain.AdbPropertySnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProtocolResponseKind
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProtocolSnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeReport
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeSample
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeStage
import com.eltavine.duckdetector.features.adbruntime.domain.AdbSocketPresence
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

    @Test
    fun socketContradictionBecomesDangerRowWithoutEndpoint() {
        val sample = AdbRuntimeSample(
            usbDebuggingEnabled = false,
            debuggingFeaturesRestricted = false,
            properties = AdbPropertySnapshot(
                testHarnessMode = "0",
                initAdbdState = "stopped",
            ),
            initSocket = AdbInitSocketSnapshot(
                state = AdbProbeState.OBSERVED,
                presence = AdbSocketPresence.PRESENT_DENIED,
            ),
        )
        val model = mapper.map(
            AdbRuntimeReport(
                stage = AdbRuntimeStage.READY,
                platformApiLevel = 37,
                samples = listOf(sample, sample),
                probed = true,
            ),
        )

        assertEquals(DetectorStatus.danger(), model.status)
        val finding = model.signalRows.single()
        assertEquals("ADB init socket vs init", finding.label)
        assertEquals(DetectorStatus.danger(), finding.status)
        assertTrue(finding.detail.orEmpty().contains("init.svc.adbd"))
        // Socket-only contradictions must not escalate the protocol-specific method.
        val protocolMethod = model.methodRows.single { it.label == "ADB protocol vs init" }
        assertEquals("Not established", protocolMethod.value)
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), protocolMethod.status)
    }

    @Test
    fun severalContradictionsKeepOneRowAndOneDangerEach() {
        val sample = AdbRuntimeSample(
            usbDebuggingEnabled = false,
            debuggingFeaturesRestricted = false,
            properties = AdbPropertySnapshot(testHarnessMode = "0", initAdbdState = "stopped"),
            initSocket = AdbInitSocketSnapshot(
                state = AdbProbeState.OBSERVED,
                presence = AdbSocketPresence.PRESENT_DENIED,
            ),
            jdwpSocket = AdbJdwpSocketSnapshot(abstract = AdbProbeState.OBSERVED),
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
                platformApiLevel = 37,
                samples = listOf(sample, sample),
                mdnsSamples = listOf(mdns, mdns),
                probed = true,
            ),
        )

        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals(3, model.signalRows.size)
        assertTrue(model.signalRows.all { it.status == DetectorStatus.danger() })
        assertEquals("3 runtime contradiction(s)", model.verdict)
    }

    @Test
    fun activeSourcesAreWarningsWithoutInventingContradictions() {
        val model = mapper.map(AdbRuntimeReport(
            stage = AdbRuntimeStage.READY, probed = true,
            samples = listOf(AdbRuntimeSample(
                usbDebuggingEnabled = true, debuggingFeaturesRestricted = false,
                properties = AdbPropertySnapshot(initAdbdState = "running", sysUsbState = "adb"),
                usb = UsbRuntimeSnapshot(AdbProbeState.OBSERVED, functions = setOf("adb")),
            )),
        ))
        assertEquals(DetectorStatus.warning(), model.status)
        assertTrue(model.signalRows.isEmpty())
        assertEquals(DetectorStatus.warning(), model.scanRows.single { it.label == "USB debugging setting" }.status)
        assertEquals(DetectorStatus.warning(), model.scanRows.single { it.label == "USB runtime" }.status)
        assertEquals(4, model.headerFacts.size)
        assertEquals("Active", model.headerFacts.single { it.label == "ADB" }.value)
        assertTrue(model.impactRows.single().detail.orEmpty().contains("does not establish root"))
        assertTrue(model.toDetectorReport().quickFacts.isNotEmpty())
    }

    @Test
    fun initSocketRowSeparatesPresentAbsentAndUnobservableStates() {
        fun rows(socket: AdbInitSocketSnapshot, initState: String = "stopped") = mapper.map(AdbRuntimeReport(
            stage = AdbRuntimeStage.READY, probed = true,
            samples = listOf(AdbRuntimeSample(
                usbDebuggingEnabled = false, debuggingFeaturesRestricted = false,
                properties = AdbPropertySnapshot(initAdbdState = initState),
                usb = UsbRuntimeSnapshot(AdbProbeState.OBSERVED),
                initSocket = socket,
            )),
        )).scanRows.single { it.label == "init socket" }

        val present = rows(AdbInitSocketSnapshot(AdbProbeState.OBSERVED, AdbSocketPresence.PRESENT),
            initState = "running")
        assertEquals("Present", present.value)
        assertEquals(DetectorStatus.warning(), present.status)

        val denied = rows(
            AdbInitSocketSnapshot(AdbProbeState.OBSERVED, AdbSocketPresence.PRESENT_DENIED,
                "stat(/dev/socket/adbd) was refused"),
            initState = "running",
        )
        assertEquals("Present (label denied)", denied.value)
        assertEquals(DetectorStatus.warning(), denied.status)
        assertTrue(denied.detail.orEmpty().contains("/dev/socket/adbd"))

        val absent = rows(AdbInitSocketSnapshot(AdbProbeState.NOT_OBSERVED, AdbSocketPresence.ABSENT))
        assertEquals("Absent", absent.value)
        assertEquals(DetectorStatus.allClear(), absent.status)

        val limited = rows(AdbInitSocketSnapshot(AdbProbeState.PERMISSION_REQUIRED))
        assertEquals("Permission required", limited.value)
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), limited.status)

        val disagreement = rows(AdbInitSocketSnapshot(AdbProbeState.OBSERVED, AdbSocketPresence.PRESENT),
            initState = "stopped")
        assertEquals("Present, init reports stopped", disagreement.value)
        assertTrue(disagreement.detail.orEmpty().contains("removes the socket before"))
    }

    @Test
    fun restrictedAndTestHarnessSettingsRemainContextOnly() {
        for (sample in listOf(
            AdbRuntimeSample(usbDebuggingEnabled = true, debuggingFeaturesRestricted = true),
            AdbRuntimeSample(usbDebuggingEnabled = true, debuggingFeaturesRestricted = false,
                properties = AdbPropertySnapshot(testHarnessMode = "1")),
        )) {
            val model = mapper.map(AdbRuntimeReport(AdbRuntimeStage.READY, platformApiLevel = 33,
                samples = listOf(sample), probed = true))
            assertEquals(DetectorStatus.info(InfoKind.SUPPORT), model.scanRows.single { it.label == "USB debugging setting" }.status)
        }
    }

    @Test
    fun failedAndPermissionLimitedSourcesDoNotBecomeCleanRows() {
        val failed = mapper.map(AdbRuntimeReport.failed("service failed"))
        assertEquals(DetectorStatus.info(InfoKind.ERROR), failed.scanRows.single().status)
        assertTrue(failed.methodRows.all { it.status == DetectorStatus.info(InfoKind.ERROR) })
        assertTrue(failed.headerFacts.all { it.status == DetectorStatus.info(InfoKind.ERROR) })
        val limited = mapper.map(AdbRuntimeReport(AdbRuntimeStage.READY, samples = emptyList(), probed = false,
            mdnsSamples = listOf(AdbMdnsSnapshot(AdbProbeState.PERMISSION_REQUIRED))))
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), limited.methodRows.single { it.label == "ADB mDNS" }.status)
        assertTrue(limited.scanRows.any { it.value == "Permission required" })
    }

    @Test
    fun resolvedListenerRetainsDiscoveryAndProtocolFailureDetails() {
        val mdns = AdbMdnsSnapshot(
            state = AdbProbeState.OBSERVED,
            serviceKind = AdbMdnsServiceKind.LEGACY_TCP,
            address = "192.0.2.5", port = 5555,
            detail = "Resolved local listener",
            protocol = AdbProtocolSnapshot(AdbProbeState.UNAVAILABLE, detail = "Handshake timed out"),
        )
        val model = mapper.map(AdbRuntimeReport(AdbRuntimeStage.READY,
            samples = emptyList(), mdnsSamples = listOf(mdns), probed = true))
        val row = model.methodRows.single { it.label == "ADB mDNS" }
        assertEquals(DetectorStatus.warning(), row.status)
        assertTrue(row.detail.orEmpty().contains("192.0.2.5:5555"))
        assertTrue(row.detail.orEmpty().contains("Resolved local listener"))
        assertTrue(row.detail.orEmpty().contains("Handshake timed out"))
        assertEquals(DetectorStatus.info(InfoKind.ERROR), model.methodRows.single { it.label == "ADB protocol vs init" }.status)
        val export = model.toDetectorReport().blocks.filterIsInstance<ReportBlock.Rows>()
            .single { it.title == "Detection methods" }.rows.single { it.label == "ADB mDNS" }
        assertEquals(row.detail, export.detail)
    }
}
