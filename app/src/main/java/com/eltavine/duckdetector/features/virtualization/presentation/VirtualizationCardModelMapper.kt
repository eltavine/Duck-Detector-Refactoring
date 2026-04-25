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

package com.eltavine.duckdetector.features.virtualization.presentation

import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility
import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationImpact
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationMethodOutcome
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationMethodResult
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationReport
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignal
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationStage
import com.eltavine.duckdetector.features.virtualization.ui.model.VirtualizationCardModel
import com.eltavine.duckdetector.features.virtualization.ui.model.VirtualizationDetailRowModel
import com.eltavine.duckdetector.features.virtualization.ui.model.VirtualizationHeaderFactModel
import com.eltavine.duckdetector.features.virtualization.ui.model.VirtualizationImpactItemModel

class VirtualizationCardModelMapper {

    fun map(report: VirtualizationReport): VirtualizationCardModel {
        return VirtualizationCardModel(
            title = "Virtualization",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            environmentRows = buildRows(
                report.stage,
                report.environmentRows,
                listOf("ro.kernel.qemu", "Build cluster", "QEMU guest properties"),
            ),
            runtimeRows = buildRows(
                report.stage,
                report.runtimeRows,
                listOf("qemud service", "AVF runtime", "Emulator device node", "Host dex path"),
            ),
            consistencyRows = buildRows(
                report.stage,
                report.consistencyRows,
                listOf(
                    "Classpath/source mismatch",
                    "Current package missing from UID",
                    "Cross-process path drift"
                ),
            ),
            honeypotRows = buildRows(
                report.stage,
                report.honeypotRows,
                listOf("Native timing trap", "ASM counter trap", "Sacrificial openat2"),
            ),
            hostAppRows = buildRows(
                report.stage,
                report.hostAppRows,
                listOf("VMOS", "Parallel Space", "VirtualXposed"),
            ),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
            references = REFERENCES,
        )
    }

    private fun buildSubtitle(report: VirtualizationReport): String {
        return when (report.stage) {
            VirtualizationStage.LOADING -> "properties + build + runtime artifacts + helper process + honeypots"
            VirtualizationStage.FAILED -> "local virtualization scan failed"
            VirtualizationStage.READY -> buildString {
                append("${report.environmentHitCount} env · ${report.translationHitCount} translation · ${report.runtimeArtifactHitCount} runtime")
                if (report.dexPathHitCount > 0) {
                    append(" · ${report.dexPathHitCount} dex")
                }
                if (report.uidIdentityHitCount > 0) {
                    append(" · ${report.uidIdentityHitCount} uid")
                }
                if (report.honeypotHitCount > 0) {
                    append(" · ${report.honeypotHitCount} trap hit(s)")
                }
                if (report.hostAppCorroborationCount > 0) {
                    append(" · ${report.hostAppCorroborationCount} host app(s)")
                }
            }
        }
    }

    private fun buildVerdict(report: VirtualizationReport): String {
        return when (report.stage) {
            VirtualizationStage.LOADING -> "Scanning virtualization and translation state"
            VirtualizationStage.FAILED -> "Virtualization scan failed"
            VirtualizationStage.READY -> when {
                report.dangerSignals.isNotEmpty() -> "${report.dangerSignals.size} direct virtualization signal(s)"
                report.warningSignals.isNotEmpty() -> "${report.warningSignals.size} virtualization signal(s) need review"
                report.onlyHostAppCorroboration -> "${report.hostAppCorroborationCount} corroborating host app(s)"
                else -> "No direct virtualization signal"
            }
        }
    }

    private fun buildSummary(report: VirtualizationReport): String {
        return when (report.stage) {
            VirtualizationStage.LOADING ->
                "Properties, Build fields, runtime artifacts, startup preload, helper-process consistency, and native or ASM honeypots are collecting local evidence."

            VirtualizationStage.FAILED ->
                report.errorMessage
                    ?: "Virtualization scan failed before evidence could be assembled."

            VirtualizationStage.READY -> when {
                report.dangerSignals.isNotEmpty() ->
                    "The current app context contains direct emulator, AVF guest, device-node, classpath, UID, or runtime-service evidence."

                report.warningSignals.isNotEmpty() ->
                    "The app is not conclusively inside a guest, but translation, renderer, classpath drift, consistency drift, or honeypot anomalies still require review."

                report.onlyHostAppCorroboration ->
                    "Known virtualization host apps are present on the device, but current process probes did not confirm guest execution."

                else ->
                    "No direct emulator, AVF guest, native-bridge, or cross-process drift artifact surfaced from the current app context."
            }
        }
    }

    private fun buildHeaderFacts(report: VirtualizationReport): List<VirtualizationHeaderFactModel> {
        return when (report.stage) {
            VirtualizationStage.LOADING -> placeholderFacts(
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            VirtualizationStage.FAILED -> placeholderFacts(
                "Error",
                DetectorStatus.info(InfoKind.ERROR)
            )

            VirtualizationStage.READY -> listOf(
                VirtualizationHeaderFactModel(
                    label = "Danger",
                    value = report.dangerSignals.size.toString(),
                    status = if (report.dangerSignals.isEmpty()) DetectorStatus.allClear() else DetectorStatus.danger(),
                ),
                VirtualizationHeaderFactModel(
                    label = "Review",
                    value = report.warningSignals.size.toString(),
                    status = if (report.warningSignals.isEmpty()) DetectorStatus.allClear() else DetectorStatus.warning(),
                ),
                VirtualizationHeaderFactModel(
                    label = "Host",
                    value = report.hostAppCorroborationCount.toString(),
                    status = if (report.hostAppCorroborationCount == 0) {
                        DetectorStatus.allClear()
                    } else {
                        DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                VirtualizationHeaderFactModel(
                    label = "Native",
                    value = if (report.nativeAvailable) "Loaded" else "N/A",
                    status = if (report.nativeAvailable) {
                        DetectorStatus.allClear()
                    } else {
                        DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
            )
        }
    }

    private fun buildRows(
        stage: VirtualizationStage,
        rows: List<VirtualizationSignal>,
        placeholders: List<String>,
    ): List<VirtualizationDetailRowModel> {
        return when (stage) {
            VirtualizationStage.LOADING -> placeholderRows(
                placeholders,
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT),
            )

            VirtualizationStage.FAILED -> placeholderRows(
                placeholders,
                "Error",
                DetectorStatus.info(InfoKind.ERROR),
            )

            VirtualizationStage.READY -> if (rows.isEmpty()) {
                listOf(
                    VirtualizationDetailRowModel(
                        label = "Status",
                        value = "Clean",
                        status = DetectorStatus.allClear(),
                        detail = "No findings were produced for this section.",
                    ),
                )
            } else {
                rows.map(::signalRow)
            }
        }
    }

    private fun buildImpactItems(report: VirtualizationReport): List<VirtualizationImpactItemModel> {
        return when (report.stage) {
            VirtualizationStage.LOADING -> listOf(
                VirtualizationImpactItemModel(
                    text = "Gathering current-process guest and translation evidence.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            VirtualizationStage.FAILED -> listOf(
                VirtualizationImpactItemModel(
                    text = report.errorMessage ?: "Virtualization scan failed.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            VirtualizationStage.READY -> report.impacts.map { impact ->
                VirtualizationImpactItemModel(
                    text = impact.text,
                    status = impact.toStatus(),
                )
            }
        }
    }

    private fun buildMethodRows(report: VirtualizationReport): List<VirtualizationDetailRowModel> {
        return when (report.stage) {
            VirtualizationStage.LOADING -> placeholderRows(
                METHOD_LABELS,
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT),
            )

            VirtualizationStage.FAILED -> placeholderRows(
                METHOD_LABELS,
                "Failed",
                DetectorStatus.info(InfoKind.ERROR),
            )

            VirtualizationStage.READY -> report.methods.map { result ->
                VirtualizationDetailRowModel(
                    label = result.label,
                    value = result.summary,
                    status = result.toStatus(),
                    detail = result.detail,
                    detailMonospace = true,
                )
            }
        }
    }

    private fun buildScanRows(report: VirtualizationReport): List<VirtualizationDetailRowModel> {
        return when (report.stage) {
            VirtualizationStage.LOADING -> placeholderRows(
                SCAN_LABELS,
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT),
            )

            VirtualizationStage.FAILED -> placeholderRows(
                SCAN_LABELS,
                "Error",
                DetectorStatus.info(InfoKind.ERROR),
            )

            VirtualizationStage.READY -> listOf(
                VirtualizationDetailRowModel(
                    label = "Startup preload",
                    value = if (report.startupPreloadAvailable) "Ready" else "Unavailable",
                    status = if (report.startupPreloadAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT,
                    ),
                ),
                VirtualizationDetailRowModel(
                    label = "Preload context",
                    value = yesNo(report.startupPreloadContextValid),
                    status = if (report.startupPreloadContextValid) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT,
                    ),
                ),
                VirtualizationDetailRowModel(
                    label = "Cross-process helper",
                    value = if (report.crossProcessAvailable) "Ready" else "Unavailable",
                    status = if (report.crossProcessAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT,
                    ),
                ),
                VirtualizationDetailRowModel(
                    label = "Isolated helper",
                    value = if (report.isolatedProcessAvailable) "Ready" else "Unavailable",
                    status = if (report.isolatedProcessAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT,
                    ),
                ),
                VirtualizationDetailRowModel(
                    label = "Package visibility",
                    value = when (report.packageVisibility) {
                        InstalledPackageVisibility.FULL -> "Full"
                        InstalledPackageVisibility.RESTRICTED -> "Scoped"
                        InstalledPackageVisibility.UNKNOWN -> "Unknown"
                    },
                    status = if (report.packageVisibility == InstalledPackageVisibility.RESTRICTED) {
                        DetectorStatus.info(InfoKind.SUPPORT)
                    } else {
                        DetectorStatus.allClear()
                    },
                ),
                VirtualizationDetailRowModel(
                    label = "Maps scanned",
                    value = report.mapLineCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                VirtualizationDetailRowModel(
                    label = "FD entries",
                    value = report.fdCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                VirtualizationDetailRowModel(
                    label = "Mountinfo lines",
                    value = report.mountInfoCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                VirtualizationDetailRowModel(
                    label = "EGL renderer",
                    value = if (report.eglAvailable) "Ready" else "Unavailable",
                    status = if (report.eglAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT,
                    ),
                ),
                VirtualizationDetailRowModel(
                    label = "Dex paths",
                    value = report.dexPathEntryCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                VirtualizationDetailRowModel(
                    label = "Dex path hits",
                    value = report.dexPathHitCount.toString(),
                    status = severityStatus(report.dexPathHitCount),
                ),
                VirtualizationDetailRowModel(
                    label = "UID identity hits",
                    value = report.uidIdentityHitCount.toString(),
                    status = severityStatus(report.uidIdentityHitCount),
                ),
                VirtualizationDetailRowModel(
                    label = "Mount namespace",
                    value = if (report.mountNamespaceAvailable) "Ready" else "Unavailable",
                    status = if (report.mountNamespaceAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT,
                    ),
                ),
                VirtualizationDetailRowModel(
                    label = "Mount anchor drift",
                    value = report.mountAnchorDriftCount.toString(),
                    status = severityStatus(report.mountAnchorDriftCount),
                ),
                VirtualizationDetailRowModel(
                    label = "Environment hits",
                    value = report.environmentHitCount.toString(),
                    status = severityStatus(report.environmentHitCount),
                ),
                VirtualizationDetailRowModel(
                    label = "Translation hits",
                    value = report.translationHitCount.toString(),
                    status = severityStatus(report.translationHitCount),
                ),
                VirtualizationDetailRowModel(
                    label = "Runtime hits",
                    value = report.runtimeArtifactHitCount.toString(),
                    status = severityStatus(report.runtimeArtifactHitCount),
                ),
                VirtualizationDetailRowModel(
                    label = "Consistency hits",
                    value = report.consistencyHitCount.toString(),
                    status = severityStatus(report.consistencyHitCount),
                ),
                VirtualizationDetailRowModel(
                    label = "Isolated consistency",
                    value = report.isolatedConsistencyHitCount.toString(),
                    status = severityStatus(report.isolatedConsistencyHitCount),
                ),
                VirtualizationDetailRowModel(
                    label = "Honeypot hits",
                    value = report.honeypotHitCount.toString(),
                    status = severityStatus(report.honeypotHitCount),
                ),
                VirtualizationDetailRowModel(
                    label = "Syscall pack",
                    value = if (report.syscallPackSupported) "Ready" else "Unsupported",
                    status = if (report.syscallPackSupported) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT,
                    ),
                ),
                VirtualizationDetailRowModel(
                    label = "Syscall pack hits",
                    value = report.syscallPackHitCount.toString(),
                    status = severityStatus(report.syscallPackHitCount),
                ),
            )
        }
    }

    private fun signalRow(signal: VirtualizationSignal): VirtualizationDetailRowModel {
        return VirtualizationDetailRowModel(
            label = signal.label,
            value = signal.value,
            status = signal.toStatus(),
            detail = signal.detail,
            detailMonospace = signal.detailMonospace,
        )
    }

    private fun VirtualizationSignal.toStatus(): DetectorStatus {
        return when (severity) {
            VirtualizationSignalSeverity.DANGER -> DetectorStatus.danger()
            VirtualizationSignalSeverity.WARNING -> DetectorStatus.warning()
            VirtualizationSignalSeverity.INFO -> DetectorStatus.info(InfoKind.SUPPORT)
            VirtualizationSignalSeverity.SAFE -> DetectorStatus.allClear()
        }
    }

    private fun VirtualizationMethodResult.toStatus(): DetectorStatus {
        return when (outcome) {
            VirtualizationMethodOutcome.DANGER -> DetectorStatus.danger()
            VirtualizationMethodOutcome.WARNING -> DetectorStatus.warning()
            VirtualizationMethodOutcome.INFO -> DetectorStatus.info(InfoKind.SUPPORT)
            VirtualizationMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
            VirtualizationMethodOutcome.CLEAN -> DetectorStatus.allClear()
        }
    }

    private fun VirtualizationImpact.toStatus(): DetectorStatus {
        return when (severity) {
            VirtualizationSignalSeverity.DANGER -> DetectorStatus.danger()
            VirtualizationSignalSeverity.WARNING -> DetectorStatus.warning()
            VirtualizationSignalSeverity.INFO -> DetectorStatus.info(InfoKind.SUPPORT)
            VirtualizationSignalSeverity.SAFE -> DetectorStatus.allClear()
        }
    }

    private fun VirtualizationReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            VirtualizationStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            VirtualizationStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            VirtualizationStage.READY -> when {
                dangerSignals.isNotEmpty() -> DetectorStatus.danger()
                warningSignals.isNotEmpty() -> DetectorStatus.warning()
                onlyHostAppCorroboration -> DetectorStatus.info(InfoKind.SUPPORT)
                else -> DetectorStatus.allClear()
            }
        }
    }

    private fun placeholderRows(
        labels: List<String>,
        value: String,
        status: DetectorStatus,
    ): List<VirtualizationDetailRowModel> {
        return labels.map { label ->
            VirtualizationDetailRowModel(label = label, value = value, status = status)
        }
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus,
    ): List<VirtualizationHeaderFactModel> {
        return listOf(
            VirtualizationHeaderFactModel("Danger", value, status),
            VirtualizationHeaderFactModel("Review", value, status),
            VirtualizationHeaderFactModel("Host", value, status),
            VirtualizationHeaderFactModel("Native", value, status),
        )
    }

    private fun yesNo(value: Boolean): String = if (value) "Yes" else "No"

    private fun severityStatus(count: Int): DetectorStatus {
        return if (count > 0) DetectorStatus.warning() else DetectorStatus.allClear()
    }

    companion object {
        private val METHOD_LABELS = listOf(
            "Properties and build",
            "Dex and classpath",
            "UID identity",
            "Runtime artifacts",
            "Graphics renderer",
            "Native bridge",
            "Startup preload",
            "Cross-process consistency",
            "Isolated-process consistency",
            "Host apps",
            "Native honeypots",
            "ASM honeypots",
            "Sacrificial syscall pack",
        )
        private val SCAN_LABELS = listOf(
            "Startup preload",
            "Preload context",
            "Cross-process helper",
            "Isolated helper",
            "Package visibility",
            "Maps scanned",
            "FD entries",
            "Mountinfo lines",
            "EGL renderer",
            "Dex paths",
            "Dex path hits",
            "UID identity hits",
            "Mount namespace",
            "Mount anchor drift",
            "Environment hits",
            "Translation hits",
            "Runtime hits",
            "Consistency hits",
            "Isolated consistency",
            "Honeypot hits",
            "Syscall pack",
            "Syscall pack hits",
        )
        private val REFERENCES = listOf(
            "Android Virtualization Framework: https://source.android.com/docs/core/virtualization",
            "Android Emulator: https://developer.android.com/studio/run/emulator",
            "AOSP property_contexts: https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/main/private/property_contexts",
        )
    }
}
