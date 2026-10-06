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
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeFinding
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeReport
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeSample
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeStage
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
                report.isAdbActive() ->
                    "ADB is enabled or runtime activity was observed; no persistent hard runtime contradiction was confirmed."
                !report.probed ->
                    report.unavailableReason ?: "No ADB state source was observable from this app process."
                else ->
                    "No persistent contradiction was observed across the ADB state sources that were available."
            }
        }

    private fun findingRow(finding: AdbRuntimeFinding): AdbRuntimeDetailRowModel =
        AdbRuntimeDetailRowModel(
            label = finding.kind.label(),
            value = "Contradiction",
            status = DetectorStatus.danger(),
            detail = finding.detail,
        )

    private fun scanRows(report: AdbRuntimeReport): List<AdbRuntimeDetailRowModel> {
        if (report.stage != AdbRuntimeStage.READY) {
            return emptyList()
        }
        val sample = report.samples.lastOrNull() ?: return listOf(
            infoRow("Probe", "Unavailable", report.unavailableReason),
        )
        return buildList {
            add(infoRow("Platform API", report.platformApiLevel?.toString() ?: "Unavailable"))
            add(infoRow("Debugging restricted", sample.debuggingFeaturesRestricted.enabledLabel()))
            add(infoRow("Test harness mode", sample.properties.testHarnessMode ?: "Unavailable"))
            add(infoRow("USB debugging setting", sample.usbDebuggingEnabled.enabledLabel()))
            add(infoRow("Wireless debugging setting", sample.wirelessDebuggingEnabled.enabledLabel()))
            add(infoRow("init.svc.adbd", sample.properties.initAdbdState ?: "Unavailable"))
            add(usbRuntimeRow(sample))
            add(mdnsRow(report.mdns))
            add(infoRow("sys.usb.state", sample.properties.sysUsbState ?: "Unavailable"))
            add(
                infoRow(
                    "service.adb.root",
                    sample.properties.serviceAdbRoot ?: "Absent / unavailable",
                    buildString {
                        sample.properties.serviceAdbRootSource?.let { source ->
                            append("Property source=")
                            append(source)
                        }
                        sample.properties.serviceAdbRootDetail?.let { detail ->
                            if (isNotEmpty()) append(". ")
                            append(detail)
                        }
                    }.ifBlank { null },
                ),
            )
        }
    }

    private fun usbRuntimeRow(sample: AdbRuntimeSample): AdbRuntimeDetailRowModel {
        val usb = sample.usb
        val value = when (usb.state) {
            AdbProbeState.OBSERVED, AdbProbeState.NOT_OBSERVED ->
                usb.functions.takeIf(Set<String>::isNotEmpty)?.joinToString(",") ?: "No functions"
            AdbProbeState.PERMISSION_REQUIRED -> "Permission required"
            AdbProbeState.UNSUPPORTED -> "Unsupported"
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
            AdbProbeState.UNSUPPORTED -> "Unsupported"
            AdbProbeState.UNAVAILABLE -> "Unavailable"
        }
        val endpoint = if (mdns.address != null && mdns.port != null) {
            buildString {
                append("${mdns.address}:${mdns.port}")
                append("; protocol=")
                append(
                    when {
                        mdns.protocol.confirmed -> mdns.protocol.responseKind?.name ?: "confirmed"
                        mdns.protocol.state == AdbProbeState.NOT_OBSERVED -> "not confirmed"
                        mdns.protocol.state == AdbProbeState.UNAVAILABLE -> "unavailable"
                        else -> "not probed"
                    },
                )
            }
        } else {
            null
        }
        return infoRow("ADB mDNS", value, endpoint ?: mdns.detail)
    }

    private fun infoRow(label: String, value: String, detail: String? = null) =
        AdbRuntimeDetailRowModel(
            label = label,
            value = value,
            status = DetectorStatus.info(InfoKind.SUPPORT),
            detail = detail,
        )

    private fun AdbFindingKind.label(): String = when (this) {
        AdbFindingKind.ADB_ROOT_PROPERTY -> "ADB root property"
        AdbFindingKind.INIT_STOPPED_WITH_ADB_PROTOCOL -> "ADB protocol vs init"
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
