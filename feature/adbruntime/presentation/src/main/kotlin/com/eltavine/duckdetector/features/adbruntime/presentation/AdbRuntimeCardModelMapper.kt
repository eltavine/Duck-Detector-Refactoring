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
import com.eltavine.duckdetector.features.adbruntime.domain.AdbFindingKind
import com.eltavine.duckdetector.features.adbruntime.domain.AdbMdnsServiceKind
import com.eltavine.duckdetector.features.adbruntime.domain.AdbMdnsSnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProbeState
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProtocolResponseKind
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProtocolSnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRootRisk
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeFinding
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeReport
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeSample
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeStage
import com.eltavine.duckdetector.features.adbruntime.domain.adbRootRisk
import com.eltavine.duckdetector.features.adbruntime.domain.findings
import com.eltavine.duckdetector.features.adbruntime.domain.isAdbActive
import com.eltavine.duckdetector.features.adbruntime.domain.toDetectorStatus
import com.eltavine.duckdetector.features.adbruntime.presentation.model.AdbRuntimeCardModel
import com.eltavine.duckdetector.features.adbruntime.presentation.model.AdbRuntimeDetailRowModel

/** Projects the domain verdict and raw source observations without re-deciding detector semantics. */
class AdbRuntimeCardModelMapper {

    fun map(report: AdbRuntimeReport): AdbRuntimeCardModel {
        val findings = report.findings()
        return AdbRuntimeCardModel(
            title = TITLE,
            subtitle = SUBTITLE,
            status = report.toDetectorStatus(),
            verdict = verdict(report, findings),
            summary = summary(report, findings),
            riskRows = rootRiskRows(report),
            signalRows = findings.map(::findingRow),
            scanRows = scanRows(report),
        )
    }

    private fun verdict(report: AdbRuntimeReport, findings: List<AdbRuntimeFinding>): String =
        when (report.stage) {
            AdbRuntimeStage.LOADING -> "Scanning"
            AdbRuntimeStage.FAILED -> "Scan failed"
            AdbRuntimeStage.READY -> when {
                findings.isNotEmpty() -> "Runtime contradiction"
                report.adbRootRisk() == AdbRootRisk.ROOT_CAPABLE -> "ADB root request"
                report.adbRootRisk() == AdbRootRisk.MARKER -> "ADB root marker"
                report.isAdbActive() -> "ADB enabled"
                !report.probed -> "Not evaluated"
                else -> "ADB state consistent"
            }
        }

    private fun summary(report: AdbRuntimeReport, findings: List<AdbRuntimeFinding>): String =
        when (report.stage) {
            AdbRuntimeStage.LOADING -> "Correlating Android debugging settings, USB runtime, properties and wireless ADB discovery."
            AdbRuntimeStage.FAILED -> report.errorMessage ?: "The scan failed before it collected evidence."
            AdbRuntimeStage.READY -> when {
                findings.isNotEmpty() ->
                    "Independent ADB state sources disagree. The rows below show the persistent contradictions."
                report.adbRootRisk() == AdbRootRisk.ROOT_CAPABLE ->
                    "service.adb.root=1 is present on a debuggable build, so AOSP adbd can honor the root request."
                report.adbRootRisk() == AdbRootRisk.MARKER ->
                    "service.adb.root=1 is present, but this marker alone does not prove that adbd retained UID 0."
                report.isAdbActive() ->
                    "ADB is enabled or runtime activity was observed; no persistent hard runtime contradiction was confirmed."
                !report.probed ->
                    report.unavailableReason ?: "No ADB state source was observable from this app process."
                else ->
                    "No persistent contradiction or ADB root risk was observed across the available sources."
            }
        }


    private fun rootRiskRows(report: AdbRuntimeReport): List<AdbRuntimeDetailRowModel> =
        when (report.adbRootRisk()) {
            AdbRootRisk.NONE -> emptyList()
            AdbRootRisk.MARKER -> listOf(
                AdbRuntimeDetailRowModel(
                    label = "ADB root marker",
                    value = "service.adb.root=1",
                    status = DetectorStatus.warning(),
                    detail = "The ADB root marker is present, but ro.debuggable is not 1, so this alone does not prove that adbd retained UID 0.",
                ),
            )
            AdbRootRisk.ROOT_CAPABLE -> listOf(
                AdbRuntimeDetailRowModel(
                    label = "ADB root request",
                    value = "service.adb.root=1",
                    status = DetectorStatus.danger(),
                    detail = "service.adb.root=1 and ro.debuggable=1 allow AOSP adbd to keep root privileges.",
                ),
            )
        }

    private fun findingRow(finding: AdbRuntimeFinding): AdbRuntimeDetailRowModel =
        AdbRuntimeDetailRowModel(
            label = finding.kind.label(),
            value = "Contradiction",
            status = DetectorStatus.danger(),
            detail = finding.detail(),
        )

    private fun AdbRuntimeFinding.detail(): String = when (kind) {
        AdbFindingKind.INIT_STOPPED_WITH_ADB_PROTOCOL ->
            "The local ${endpoint.serviceKind.label()} endpoint ${endpoint.address}:${endpoint.port} " +
                "answered with the ${endpoint.responseKind.label()} in both discovery passes while " +
                "init.svc.adbd stayed stopped."
    }

    private fun scanRows(report: AdbRuntimeReport): List<AdbRuntimeDetailRowModel> {
        if (report.stage != AdbRuntimeStage.READY) {
            return emptyList()
        }
        val sample = report.samples.lastOrNull() ?: return listOf(
            infoRow("Probe", "Unavailable", report.unavailableReason),
        )
        return listOf(
            infoRow("Platform API", report.platformApiLevel?.toString() ?: "Unavailable"),
            infoRow("Debugging restricted", sample.debuggingFeaturesRestricted.enabledLabel()),
            infoRow("Test harness mode", sample.properties.testHarnessMode ?: "Unavailable"),
            infoRow("USB debugging setting", sample.usbDebuggingEnabled.enabledLabel()),
            infoRow("Wireless debugging setting", sample.wirelessDebuggingEnabled.enabledLabel()),
            infoRow("init.svc.adbd", sample.properties.initAdbdState ?: "Unavailable"),
            usbRuntimeRow(sample),
            mdnsRow(report.latestMdns),
            infoRow("sys.usb.state", sample.properties.sysUsbState ?: "Unavailable"),
            infoRow("service.adb.root", sample.properties.serviceAdbRoot ?: "Absent / unavailable"),
            infoRow("ro.debuggable", sample.properties.roDebuggable ?: "Unavailable"),
        )
    }

    private fun usbRuntimeRow(sample: AdbRuntimeSample): AdbRuntimeDetailRowModel {
        val usb = sample.usb
        val value = when (usb.state) {
            AdbProbeState.OBSERVED, AdbProbeState.NOT_OBSERVED ->
                usb.functions.takeIf(Set<String>::isNotEmpty)?.joinToString(",") ?: "No functions"
            AdbProbeState.PERMISSION_REQUIRED -> "Permission required"
            AdbProbeState.NOT_PROBED -> "Not probed"
            AdbProbeState.UNAVAILABLE -> "Unavailable"
        }
        return infoRow(
            label = "USB runtime",
            value = value,
            detail = "connected=${usb.connected ?: "?"}, configured=${usb.configured ?: "?"}" +
                usb.detail?.let { ", $it" }.orEmpty(),
        )
    }

    private fun mdnsRow(mdns: AdbMdnsSnapshot): AdbRuntimeDetailRowModel {
        val value = when (mdns.state) {
            AdbProbeState.OBSERVED -> when (mdns.serviceKind) {
                AdbMdnsServiceKind.TLS_CONNECT -> "Local Wireless ADB TLS service"
                AdbMdnsServiceKind.LEGACY_TCP -> "Local legacy ADB TCP service"
                null -> "Local ADB service"
            }
            AdbProbeState.NOT_OBSERVED -> "Not observed"
            AdbProbeState.PERMISSION_REQUIRED -> "Permission required"
            AdbProbeState.NOT_PROBED -> "Not probed"
            AdbProbeState.UNAVAILABLE -> "Unavailable"
        }
        val detail = when {
            mdns.address != null && mdns.port != null ->
                "${mdns.address}:${mdns.port}; protocol=${mdns.protocol.label()}"
            mdns.state == AdbProbeState.PERMISSION_REQUIRED ->
                "Android 17 allows silent NsdManager discovery only with the local network permission. " +
                    "Duck Detector never asks for it during a scan; grant it in the app's system settings " +
                    "to evaluate network ADB."
            else -> mdns.detail
        }
        return infoRow("ADB mDNS", value, detail)
    }

    private fun infoRow(label: String, value: String, detail: String? = null) =
        AdbRuntimeDetailRowModel(
            label = label,
            value = value,
            status = DetectorStatus.info(InfoKind.SUPPORT),
            detail = detail,
        )

    private fun AdbFindingKind.label(): String = when (this) {
        AdbFindingKind.INIT_STOPPED_WITH_ADB_PROTOCOL -> "ADB protocol vs init"
    }

    private fun AdbMdnsServiceKind.label(): String = when (this) {
        AdbMdnsServiceKind.LEGACY_TCP -> "legacy ADB"
        AdbMdnsServiceKind.TLS_CONNECT -> "Wireless debugging secure-connect"
    }

    private fun AdbProtocolResponseKind.label(): String = when (this) {
        AdbProtocolResponseKind.AUTH_TOKEN -> "ADB AUTH token"
        AdbProtocolResponseKind.CONNECT -> "ADB CNXN banner"
        AdbProtocolResponseKind.START_TLS -> "ADB STLS request"
    }

    private fun AdbProtocolSnapshot.label(): String =
        responseKind?.takeIf { confirmed }?.label() ?: when (state) {
            AdbProbeState.OBSERVED -> "confirmed"
            AdbProbeState.NOT_OBSERVED -> "not confirmed"
            AdbProbeState.UNAVAILABLE -> "unavailable"
            AdbProbeState.PERMISSION_REQUIRED -> "permission required"
            AdbProbeState.NOT_PROBED -> "not probed"
        }

    private fun Boolean?.enabledLabel(): String = when (this) {
        true -> "Enabled"
        false -> "Disabled"
        null -> "Unavailable"
    }

    private companion object {
        const val TITLE = "ADB Runtime"
        const val SUBTITLE = "Cross-check debugging state across independent Android subsystems"
    }
}
