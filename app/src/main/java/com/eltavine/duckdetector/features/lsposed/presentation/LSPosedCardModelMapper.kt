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

package com.eltavine.duckdetector.features.lsposed.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodOutcome
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodResult
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedPackageVisibility
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedReport
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedStage
import com.eltavine.duckdetector.features.lsposed.ui.model.LSPosedCardModel
import com.eltavine.duckdetector.features.lsposed.ui.model.LSPosedDetailRowModel
import com.eltavine.duckdetector.features.lsposed.ui.model.LSPosedHeaderFactModel
import com.eltavine.duckdetector.features.lsposed.ui.model.LSPosedImpactItemModel

class LSPosedCardModelMapper {

    fun map(report: LSPosedReport): LSPosedCardModel {
        return LSPosedCardModel(
            title = "LSPosed",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            runtimeRows = buildRowsForGroup(report, LSPosedSignalGroup.RUNTIME, "Runtime probes"),
            binderRows = buildRowsForGroup(report, LSPosedSignalGroup.BINDER, "Binder probes"),
            packageRows = buildRowsForGroup(report, LSPosedSignalGroup.PACKAGES, "Packages"),
            nativeRows = buildRowsForGroup(report, LSPosedSignalGroup.NATIVE, "Native traces"),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }

    private fun buildSubtitle(report: LSPosedReport): String {
        return when (report.stage) {
            LSPosedStage.LOADING -> "class + classloader + bridge fields + callbacks + runtime + logcat + binder + zygote gids + native"
            LSPosedStage.FAILED -> "local LSPosed/Xposed scan failed"
            LSPosedStage.READY -> {
                "${report.managerPackageCount} manager · ${report.moduleAppCount} module · ${report.nativeTraceCount} native"
            }
        }
    }

    private fun buildVerdict(report: LSPosedReport): String {
        return when (report.stage) {
            LSPosedStage.LOADING -> "Scanning LSPosed/Xposed runtime and residue"
            LSPosedStage.FAILED -> "LSPosed scan failed"
            LSPosedStage.READY -> when {
                report.hasDangerSignals -> "${report.dangerSignalCount} high-risk LSPosed signal(s)"
                report.hasWarningSignals -> "${report.warningSignalCount} LSPosed residue signal(s)"
                else -> "No LSPosed/Xposed runtime signal"
            }
        }
    }

    private fun buildSummary(report: LSPosedReport): String {
        return when (report.stage) {
            LSPosedStage.LOADING ->
                "Class loading, ClassLoader chains, XposedBridge fields, callbacks, package metadata, stack traces, Binder bridges, zygote permission GID audits, runtime artifacts, logcat leaks, and LSPosed-specific native traces are collecting local evidence."

            LSPosedStage.FAILED ->
                report.errorMessage
                    ?: "LSPosed detection failed before evidence could be assembled."

            LSPosedStage.READY -> when {
                report.hasDangerSignals ->
                    "Binder bridge replies, loaded Xposed classes, XposedBridge fields, callback handlers, runtime artifacts, logcat leaks, zygote permission GID mismatches, stack trace signatures, or native LSPosed keywords point to active hook-framework presence rather than passive install residue."

                report.hasWarningSignals ->
                    "Installed managers, deep ClassLoader chains, environment residue, or pattern-only logcat traces were found, but the current process did not expose enough stronger runtime evidence to treat the framework as confirmed active here."

                else ->
                    "No Xposed class loading, ClassLoader, callback, Binder bridge, runtime artifact, logcat, stack, maps, or heap traces surfaced in the current app process."
            }
        }
    }

    private fun buildHeaderFacts(report: LSPosedReport): List<LSPosedHeaderFactModel> {
        return when (report.stage) {
            LSPosedStage.LOADING -> placeholderFacts(
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            LSPosedStage.FAILED -> placeholderFacts("Error", DetectorStatus.info(InfoKind.ERROR))
            LSPosedStage.READY -> listOf(
                LSPosedHeaderFactModel(
                    label = "Critical",
                    value = countLabel(report.dangerSignalCount),
                    status = if (report.dangerSignalCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                LSPosedHeaderFactModel(
                    label = "Review",
                    value = countLabel(report.warningSignalCount),
                    status = if (report.warningSignalCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
                ),
                LSPosedHeaderFactModel(
                    label = "Bridge",
                    value = if (report.binderHitCount > 0) report.binderHitCount.toString() else "Clean",
                    status = if (report.binderHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                LSPosedHeaderFactModel(
                    label = "Packages",
                    value = if (report.packageSignalCount > 0) report.packageSignalCount.toString() else "Clean",
                    status = if (report.packageSignalCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
                ),
            )
        }
    }

    private fun buildRowsForGroup(
        report: LSPosedReport,
        group: LSPosedSignalGroup,
        fallbackLabel: String,
    ): List<LSPosedDetailRowModel> {
        return when (report.stage) {
            LSPosedStage.LOADING -> placeholderRows(
                listOf(fallbackLabel),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending"
            )

            LSPosedStage.FAILED -> placeholderRows(
                listOf(fallbackLabel),
                DetectorStatus.info(InfoKind.ERROR),
                "Error"
            )

            LSPosedStage.READY -> {
                val rows = report.signals
                    .filter { it.group == group }
                    .map(::signalRow)
                if (rows.isNotEmpty()) {
                    rows
                } else {
                    listOf(
                        LSPosedDetailRowModel(
                            label = fallbackLabel,
                            value = "Clean",
                            status = DetectorStatus.allClear(),
                            detail = "No signal surfaced in this LSPosed evidence slice.",
                        ),
                    )
                }
            }
        }
    }

    private fun buildImpactItems(report: LSPosedReport): List<LSPosedImpactItemModel> {
        return when (report.stage) {
            LSPosedStage.LOADING -> listOf(
                LSPosedImpactItemModel(
                    text = "Gathering class, ClassLoader, Binder, runtime-artifact, logcat, package, and native runtime evidence.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            LSPosedStage.FAILED -> listOf(
                LSPosedImpactItemModel(
                    text = report.errorMessage ?: "LSPosed scan failed.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            LSPosedStage.READY -> when {
                report.hasDangerSignals -> listOf(
                    LSPosedImpactItemModel(
                        text = "Loaded Xposed classes, bridge fields, Binder bridge responses, runtime artifacts, logcat leaks, and native LSPosed keywords are stronger evidence than package residue because they touch the current process or live system services directly.",
                        status = DetectorStatus.danger(),
                    ),
                    LSPosedImpactItemModel(
                        text = "This card still observes only a narrow runtime slice. Read it together with Memory, Native Root, Mount, and System Properties when the setup is actively hiding itself.",
                        status = DetectorStatus.warning(),
                    ),
                )

                report.hasWarningSignals -> listOf(
                    LSPosedImpactItemModel(
                        text = "Manager packages or Xposed module meta-data show framework residue, but they do not prove the current process is hooked right now.",
                        status = DetectorStatus.warning(),
                    ),
                    LSPosedImpactItemModel(
                        text = "Hardened setups can avoid exposing direct stack or class evidence in the current app, so yellow-only results still deserve correlation with other detector cards.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )

                else -> listOf(
                    LSPosedImpactItemModel(
                        text = "The current app process did not expose LSPosed/Xposed class loading, Binder bridge behavior, or LSPosed-native runtime strings.",
                        status = DetectorStatus.allClear(),
                    ),
                    LSPosedImpactItemModel(
                        text = "A clean result lowers confidence in active LSPosed-style hooking for this process, but it does not prove the whole device is stock.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )
            }
        }
    }

    private fun buildMethodRows(report: LSPosedReport): List<LSPosedDetailRowModel> {
        return when (report.stage) {
            LSPosedStage.LOADING -> placeholderMethodRows(
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending"
            )

            LSPosedStage.FAILED -> placeholderMethodRows(
                DetectorStatus.info(InfoKind.ERROR),
                "Error"
            )

            LSPosedStage.READY -> report.methods.map { method ->
                LSPosedDetailRowModel(
                    label = method.label,
                    value = method.summary,
                    status = methodStatus(method),
                    detail = method.detail,
                    detailMonospace = false,
                )
            }
        }
    }

    private fun buildScanRows(report: LSPosedReport): List<LSPosedDetailRowModel> {
        return when (report.stage) {
            LSPosedStage.LOADING -> placeholderRows(
                listOf(
                    "Danger signals",
                    "Review signals",
                    "Class hits",
                    "ClassLoader hits",
                    "Bridge field hits",
                    "Stack hits",
                    "Callback hits",
                    "Binder hits",
                    "Runtime artifact hits",
                    "Runtime artifacts availability",
                    "Logcat hits",
                    "Logcat availability",
                    "Manager packages",
                    "Module apps",
                    "Native maps",
                    "Native heap",
                    "Package visibility",
                ),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending",
            )

            LSPosedStage.FAILED -> placeholderRows(
                listOf(
                    "Danger signals",
                    "Review signals",
                    "Class hits",
                    "ClassLoader hits",
                    "Bridge field hits",
                    "Stack hits",
                    "Callback hits",
                    "Binder hits",
                    "Runtime artifact hits",
                    "Runtime artifacts availability",
                    "Logcat hits",
                    "Logcat availability",
                    "Manager packages",
                    "Module apps",
                    "Native maps",
                    "Native heap",
                    "Package visibility",
                ),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
            )

            LSPosedStage.READY -> listOf(
                LSPosedDetailRowModel(
                    label = "Danger signals",
                    value = report.dangerSignalCount.toString(),
                    status = if (report.dangerSignalCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "Review signals",
                    value = report.warningSignalCount.toString(),
                    status = if (report.warningSignalCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "Class hits",
                    value = report.classHitCount.toString(),
                    status = if (report.classHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "ClassLoader hits",
                    value = report.classLoaderHitCount.toString(),
                    status = when {
                        report.signals.any {
                            it.id.startsWith("classloader_") &&
                                    it.severity == LSPosedSignalSeverity.DANGER
                        } -> DetectorStatus.danger()

                        report.classLoaderHitCount > 0 -> DetectorStatus.warning()
                        else -> DetectorStatus.allClear()
                    },
                ),
                LSPosedDetailRowModel(
                    label = "Bridge field hits",
                    value = report.bridgeFieldHitCount.toString(),
                    status = if (report.bridgeFieldHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "Stack hits",
                    value = report.stackHitCount.toString(),
                    status = if (report.stackHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "Callback hits",
                    value = report.callbackHitCount.toString(),
                    status = if (report.callbackHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "Binder hits",
                    value = report.binderHitCount.toString(),
                    status = if (report.binderHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "Runtime artifact hits",
                    value = report.runtimeArtifactHitCount.toString(),
                    status = when {
                        report.signals.any {
                            it.id.startsWith("runtime_") &&
                                    it.severity == LSPosedSignalSeverity.DANGER
                        } -> DetectorStatus.danger()

                        report.runtimeArtifactHitCount > 0 -> DetectorStatus.warning()
                        report.runtimeArtifactAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                LSPosedDetailRowModel(
                    label = "Runtime artifacts availability",
                    value = if (report.runtimeArtifactAvailable) "Checked" else "Unavailable",
                    status = if (report.runtimeArtifactAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                LSPosedDetailRowModel(
                    label = "Logcat hits",
                    value = report.logcatHitCount.toString(),
                    status = when {
                        report.signals.any {
                            it.id.startsWith("logcat_") &&
                                    it.severity == LSPosedSignalSeverity.DANGER
                        } -> DetectorStatus.danger()

                        report.logcatHitCount > 0 -> DetectorStatus.warning()
                        report.logcatAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                LSPosedDetailRowModel(
                    label = "Logcat availability",
                    value = if (report.logcatAvailable) "Checked" else "Unavailable",
                    status = if (report.logcatAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                LSPosedDetailRowModel(
                    label = "Manager packages",
                    value = report.managerPackageCount.toString(),
                    status = if (report.managerPackageCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "Module apps",
                    value = report.moduleAppCount.toString(),
                    status = if (report.moduleAppCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "Native maps",
                    value = report.nativeMapsHitCount.toString(),
                    status = if (report.nativeMapsHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "Native heap",
                    value = "${report.nativeHeapHitCount}/${report.nativeHeapScannedRegions}",
                    status = when {
                        report.nativeHeapHitCount > 0 -> DetectorStatus.danger()
                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                LSPosedDetailRowModel(
                    label = "Package visibility",
                    value = visibilityLabel(report.packageVisibility),
                    status = when (report.packageVisibility) {
                        LSPosedPackageVisibility.FULL -> DetectorStatus.allClear()
                        LSPosedPackageVisibility.RESTRICTED -> DetectorStatus.info(InfoKind.SUPPORT)
                        LSPosedPackageVisibility.UNKNOWN -> DetectorStatus.info(InfoKind.ERROR)
                    },
                ),
            )
        }
    }

    private fun signalRow(signal: LSPosedSignal): LSPosedDetailRowModel {
        return LSPosedDetailRowModel(
            label = signal.label,
            value = signal.value,
            status = signalStatus(signal),
            detail = signal.detail,
            detailMonospace = signal.detailMonospace,
        )
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus,
    ): List<LSPosedHeaderFactModel> {
        return listOf(
            LSPosedHeaderFactModel("Critical", value, status),
            LSPosedHeaderFactModel("Review", value, status),
            LSPosedHeaderFactModel("Bridge", value, status),
            LSPosedHeaderFactModel("Packages", value, status),
        )
    }

    private fun placeholderRows(
        labels: List<String>,
        status: DetectorStatus,
        value: String,
    ): List<LSPosedDetailRowModel> {
        return labels.map { label ->
            LSPosedDetailRowModel(
                label = label,
                value = value,
                status = status,
            )
        }
    }

    private fun placeholderMethodRows(
        status: DetectorStatus,
        value: String,
    ): List<LSPosedDetailRowModel> {
        return listOf(
            "Class load",
            "ClassLoader chain",
            "XposedBridge fields",
            "Package catalog",
            "Xposed meta-data",
            "Stack trace",
            "Hook callbacks",
            "Binder bridge",
            "Zygote permissions",
            "Runtime artifacts",
            "Logcat leaks",
            "Native maps",
            "Native heap",
            "Native library",
            "Signal summary",
        ).map { label ->
            LSPosedDetailRowModel(
                label = label,
                value = value,
                status = status,
            )
        }
    }

    private fun countLabel(count: Int): String {
        return if (count > 0) count.toString() else "None"
    }

    private fun visibilityLabel(
        visibility: LSPosedPackageVisibility,
    ): String {
        return when (visibility) {
            LSPosedPackageVisibility.FULL -> "Full"
            LSPosedPackageVisibility.RESTRICTED -> "Restricted"
            LSPosedPackageVisibility.UNKNOWN -> "Unknown"
        }
    }

    private fun signalStatus(signal: LSPosedSignal): DetectorStatus {
        return when (signal.severity) {
            LSPosedSignalSeverity.DANGER -> DetectorStatus.danger()
            LSPosedSignalSeverity.WARNING -> DetectorStatus.warning()
        }
    }

    private fun methodStatus(method: LSPosedMethodResult): DetectorStatus {
        return when (method.outcome) {
            LSPosedMethodOutcome.CLEAN -> DetectorStatus.allClear()
            LSPosedMethodOutcome.WARNING -> DetectorStatus.warning()
            LSPosedMethodOutcome.DETECTED -> DetectorStatus.danger()
            LSPosedMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun LSPosedReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            LSPosedStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            LSPosedStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            LSPosedStage.READY -> when {
                hasDangerSignals -> DetectorStatus.danger()
                hasWarningSignals -> DetectorStatus.warning()
                else -> DetectorStatus.allClear()
            }
        }
    }
}
