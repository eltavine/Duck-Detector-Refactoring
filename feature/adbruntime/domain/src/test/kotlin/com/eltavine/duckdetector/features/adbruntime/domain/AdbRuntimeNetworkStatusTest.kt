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

package com.eltavine.duckdetector.features.adbruntime.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AdbRuntimeNetworkStatusTest {
    @Test
    fun legacyMdnsWithoutProtocolIsActivityOnly() {
        val mdns = endpoint(AdbMdnsServiceKind.LEGACY_TCP)
        val report = report(mdns, mdns)

        assertTrue(report.findings().isEmpty())
        assertEquals(DetectorStatus.warning(), report.toDetectorStatus())
    }

    @Test
    fun confirmedLegacyProtocolContradictsStoppedInit() {
        val mdns = endpoint(
            kind = AdbMdnsServiceKind.LEGACY_TCP,
            response = AdbProtocolResponseKind.AUTH_TOKEN,
        )
        val report = report(mdns, mdns)

        assertTrue(report.findings().any { it.kind == AdbFindingKind.INIT_STOPPED_WITH_ADB_PROTOCOL })
        assertEquals(DetectorStatus.danger(), report.toDetectorStatus())
    }

    @Test
    fun wirelessMdnsWithoutProtocolIsActivityOnly() {
        val mdns = endpoint(AdbMdnsServiceKind.TLS_CONNECT)
        val report = report(mdns, mdns, wifiEnabled = true)

        assertTrue(report.findings().isEmpty())
        assertEquals(DetectorStatus.warning(), report.toDetectorStatus())
    }

    @Test
    fun confirmedStartTlsContradictsStoppedInit() {
        val mdns = endpoint(
            kind = AdbMdnsServiceKind.TLS_CONNECT,
            response = AdbProtocolResponseKind.START_TLS,
        )
        val report = report(mdns, mdns, wifiEnabled = true)

        assertTrue(report.findings().any { it.kind == AdbFindingKind.INIT_STOPPED_WITH_ADB_PROTOCOL })
        assertEquals(DetectorStatus.danger(), report.toDetectorStatus())
    }

    @Test
    fun oneShotProtocolConfirmationStaysWarning() {
        val first = endpoint(
            kind = AdbMdnsServiceKind.TLS_CONNECT,
            response = AdbProtocolResponseKind.START_TLS,
        )
        val second = endpoint(AdbMdnsServiceKind.TLS_CONNECT)
        val report = report(first, second, wifiEnabled = true)

        assertTrue(report.findings().isEmpty())
        assertEquals(DetectorStatus.warning(), report.toDetectorStatus())
    }

    @Test
    fun changingEndpointStaysWarning() {
        val first = endpoint(
            kind = AdbMdnsServiceKind.LEGACY_TCP,
            response = AdbProtocolResponseKind.CONNECT,
        )
        val second = first.copy(port = 5556)
        val report = report(first, second)

        assertTrue(report.findings().isEmpty())
        assertEquals(DetectorStatus.warning(), report.toDetectorStatus())
    }

    @Test
    fun changingServiceKindStaysWarning() {
        val first = endpoint(
            kind = AdbMdnsServiceKind.LEGACY_TCP,
            response = AdbProtocolResponseKind.AUTH_TOKEN,
        )
        val second = endpoint(
            kind = AdbMdnsServiceKind.TLS_CONNECT,
            response = AdbProtocolResponseKind.START_TLS,
        )
        val report = report(first, second, wifiEnabled = true)

        assertTrue(report.findings().isEmpty())
        assertEquals(DetectorStatus.warning(), report.toDetectorStatus())
    }

    private fun endpoint(
        kind: AdbMdnsServiceKind,
        response: AdbProtocolResponseKind? = null,
    ) = AdbMdnsSnapshot(
        state = AdbProbeState.OBSERVED,
        serviceKind = kind,
        address = "192.0.2.5",
        port = 5555,
        protocol = if (response == null) {
            AdbProtocolSnapshot()
        } else {
            AdbProtocolSnapshot(
                state = AdbProbeState.OBSERVED,
                responseKind = response,
            )
        },
    )

    private fun report(
        firstMdns: AdbMdnsSnapshot,
        secondMdns: AdbMdnsSnapshot,
        wifiEnabled: Boolean = false,
    ): AdbRuntimeReport {
        val sample = AdbRuntimeSample(
            usbDebuggingEnabled = true,
            wirelessDebuggingEnabled = wifiEnabled,
            debuggingFeaturesRestricted = false,
            properties = AdbPropertySnapshot(
                testHarnessMode = "0",
                initAdbdState = "stopped",
            ),
            usb = UsbRuntimeSnapshot(state = AdbProbeState.OBSERVED),
        )
        return AdbRuntimeReport(
            stage = AdbRuntimeStage.READY,
            platformApiLevel = 36,
            samples = listOf(sample, sample),
            mdns = secondMdns,
            mdnsSamples = listOf(firstMdns, secondMdns),
            probed = true,
        )
    }
}
