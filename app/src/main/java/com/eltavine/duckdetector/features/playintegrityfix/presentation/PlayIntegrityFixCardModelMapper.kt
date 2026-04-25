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

package com.eltavine.duckdetector.features.playintegrityfix.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixGroup
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixMethodOutcome
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixMethodResult
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixReport
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixSignal
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixSignalSeverity
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixStage
import com.eltavine.duckdetector.features.playintegrityfix.ui.model.PlayIntegrityFixCardModel
import com.eltavine.duckdetector.features.playintegrityfix.ui.model.PlayIntegrityFixDetailRowModel
import com.eltavine.duckdetector.features.playintegrityfix.ui.model.PlayIntegrityFixHeaderFactModel
import com.eltavine.duckdetector.features.playintegrityfix.ui.model.PlayIntegrityFixImpactItemModel

class PlayIntegrityFixCardModelMapper {

    fun map(
        report: PlayIntegrityFixReport,
    ): PlayIntegrityFixCardModel {
        return PlayIntegrityFixCardModel(
            title = "Play Integrity Fix",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            propertyRows = buildPropertyRows(report),
            consistencyRows = buildConsistencyRows(report),
            nativeRows = buildNativeRows(report),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }

    private fun buildSubtitle(report: PlayIntegrityFixReport): String {
        return when (report.stage) {
            PlayIntegrityFixStage.LOADING -> "multi-source props + native libc + runtime maps"
            PlayIntegrityFixStage.FAILED -> "local Play Integrity residue scan failed"
            PlayIntegrityFixStage.READY ->
                "${report.checkedPropertyCount} props · ${report.directPropertyCount} hits · ${report.consistencySignals.size} mismatch · ${report.nativeTraceCount} traces"
        }
    }

    private fun buildVerdict(report: PlayIntegrityFixReport): String {
        return when (report.stage) {
            PlayIntegrityFixStage.LOADING -> "Scanning Play Integrity residue"
            PlayIntegrityFixStage.FAILED -> "Play Integrity Fix scan failed"
            PlayIntegrityFixStage.READY -> when {
                report.dangerSignalCount > 0 -> "${report.dangerSignalCount} high-confidence residue signal(s)"
                report.warningSignalCount > 0 -> "${report.warningSignalCount} signal(s) need review"
                else -> "No Play Integrity residue surfaced"
            }
        }
    }

    private fun buildSummary(report: PlayIntegrityFixReport): String {
        return when (report.stage) {
            PlayIntegrityFixStage.LOADING ->
                "Property residue, cross-source drift, and current-process runtime traces are being collected from Java and native probes."

            PlayIntegrityFixStage.FAILED ->
                report.errorMessage
                    ?: "Play Integrity Fix scan failed before evidence could be assembled."

            PlayIntegrityFixStage.READY -> when {
                report.dangerSignalCount > 0 ->
                    "Direct spoof properties or runtime traces suggest active or recently used Play Integrity bypass infrastructure."

                report.warningSignalCount > 0 ->
                    "Only lower-confidence residue or cross-source drift surfaced. This can reflect disabled leftovers, partial cleanup, or source disagreement."

                report.nativeAvailable ->
                    "No catalogued Play Integrity residue property or runtime trace was observed across reflection, getprop, native libc, and maps checks."

                else ->
                    "Java-side checks were clean, but native property and runtime trace coverage was unavailable on this build."
            }
        }
    }

    private fun buildHeaderFacts(report: PlayIntegrityFixReport): List<PlayIntegrityFixHeaderFactModel> {
        return when (report.stage) {
            PlayIntegrityFixStage.LOADING -> placeholderFacts(
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            PlayIntegrityFixStage.FAILED -> placeholderFacts(
                "Error",
                DetectorStatus.info(InfoKind.ERROR)
            )

            PlayIntegrityFixStage.READY -> listOf(
                PlayIntegrityFixHeaderFactModel(
                    label = "Direct",
                    value = countOrNone(report.dangerSignalCount),
                    status = if (report.dangerSignalCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                PlayIntegrityFixHeaderFactModel(
                    label = "Review",
                    value = countOrNone(report.warningSignalCount),
                    status = if (report.warningSignalCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
                ),
                PlayIntegrityFixHeaderFactModel(
                    label = "Props",
                    value = countOrClean(report.directPropertyCount),
                    status = if (report.directPropertyCount > 0) propertyStatus(report) else DetectorStatus.allClear(),
                ),
                PlayIntegrityFixHeaderFactModel(
                    label = "Native",
                    value = nativeFactValue(report),
                    status = nativeFactStatus(report),
                ),
            )
        }
    }

    private fun buildPropertyRows(report: PlayIntegrityFixReport): List<PlayIntegrityFixDetailRowModel> {
        return when (report.stage) {
            PlayIntegrityFixStage.LOADING -> placeholderRows(
                labels = listOf("Spoof control", "Pixel props", "Device spoof", "Security spoof"),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
            )

            PlayIntegrityFixStage.FAILED -> placeholderRows(
                labels = listOf("Spoof control", "Pixel props", "Device spoof", "Security spoof"),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
            )

            PlayIntegrityFixStage.READY -> report.propertySignals
                .sortedWith(compareBy<PlayIntegrityFixSignal> { it.category.ordinal }.thenBy { it.label })
                .map(::signalRow)
        }
    }

    private fun buildConsistencyRows(report: PlayIntegrityFixReport): List<PlayIntegrityFixDetailRowModel> {
        return when (report.stage) {
            PlayIntegrityFixStage.LOADING -> placeholderRows(
                labels = listOf("Reflection/getprop/native alignment"),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
                monospace = true,
            )

            PlayIntegrityFixStage.FAILED -> placeholderRows(
                labels = listOf("Reflection/getprop/native alignment"),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
                monospace = true,
            )

            PlayIntegrityFixStage.READY -> report.consistencySignals
                .sortedBy { it.label }
                .map(::signalRow)
        }
    }

    private fun buildNativeRows(report: PlayIntegrityFixReport): List<PlayIntegrityFixDetailRowModel> {
        return when (report.stage) {
            PlayIntegrityFixStage.LOADING -> placeholderRows(
                labels = listOf("Maps runtime trace", "Native libc residue"),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
                monospace = true,
            )

            PlayIntegrityFixStage.FAILED -> placeholderRows(
                labels = listOf("Maps runtime trace", "Native libc residue"),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
                monospace = true,
            )

            PlayIntegrityFixStage.READY -> report.nativeSignals
                .sortedBy { it.label }
                .map(::signalRow)
        }
    }

    private fun buildImpactItems(report: PlayIntegrityFixReport): List<PlayIntegrityFixImpactItemModel> {
        return when (report.stage) {
            PlayIntegrityFixStage.LOADING -> listOf(
                PlayIntegrityFixImpactItemModel(
                    text = "Gathering residue properties and runtime trace evidence for Play Integrity spoof frameworks.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            PlayIntegrityFixStage.FAILED -> listOf(
                PlayIntegrityFixImpactItemModel(
                    text = report.errorMessage ?: "Play Integrity Fix scan failed.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            PlayIntegrityFixStage.READY -> buildList {
                if (report.propertySignals.isNotEmpty()) {
                    add(
                        PlayIntegrityFixImpactItemModel(
                            text = "Persisted spoof properties are relatively strong evidence because they survive process restarts and are readable from multiple layers.",
                            status = if (report.propertySignals.any { it.severity == PlayIntegrityFixSignalSeverity.DANGER }) {
                                DetectorStatus.danger()
                            } else {
                                DetectorStatus.warning()
                            },
                        ),
                    )
                }
                if (report.consistencySignals.isNotEmpty()) {
                    add(
                        PlayIntegrityFixImpactItemModel(
                            text = "Source mismatches mean property APIs disagree. That often points to hook-based translation, cleanup drift, or framework/native divergence.",
                            status = DetectorStatus.warning(),
                        ),
                    )
                }
                if (report.nativeSignals.isNotEmpty()) {
                    add(
                        PlayIntegrityFixImpactItemModel(
                            text = "Runtime traces in current-process maps can indicate bypass code, deleted artifacts, or keystore-adjacent tampering still touching the app process.",
                            status = if (report.nativeSignals.any { it.severity == PlayIntegrityFixSignalSeverity.DANGER }) {
                                DetectorStatus.danger()
                            } else {
                                DetectorStatus.warning()
                            },
                        ),
                    )
                }
                if (isEmpty()) {
                    add(
                        PlayIntegrityFixImpactItemModel(
                            text = "No common Play Integrity Fix residue surfaced from the current property catalog or runtime trace heuristics.",
                            status = DetectorStatus.allClear(),
                        ),
                    )
                }
                if (!report.nativeAvailable) {
                    add(
                        PlayIntegrityFixImpactItemModel(
                            text = "Native coverage was unavailable, so a clean result here is weaker than when libc and maps probes both run successfully.",
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                        ),
                    )
                } else {
                    add(
                        PlayIntegrityFixImpactItemModel(
                            text = "Absence of residue is not proof of stock state. A determined bypass can clean properties and avoid obvious in-process traces.",
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                        ),
                    )
                }
            }
        }
    }

    private fun buildMethodRows(report: PlayIntegrityFixReport): List<PlayIntegrityFixDetailRowModel> {
        return when (report.stage) {
            PlayIntegrityFixStage.LOADING -> placeholderMethodRows(
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending"
            )

            PlayIntegrityFixStage.FAILED -> placeholderMethodRows(
                DetectorStatus.info(InfoKind.ERROR),
                "Failed"
            )

            PlayIntegrityFixStage.READY -> report.methods.map { result ->
                PlayIntegrityFixDetailRowModel(
                    label = result.label,
                    value = result.summary,
                    status = methodStatus(result),
                    detail = result.detail,
                    detailMonospace = true,
                )
            }
        }
    }

    private fun buildScanRows(report: PlayIntegrityFixReport): List<PlayIntegrityFixDetailRowModel> {
        return when (report.stage) {
            PlayIntegrityFixStage.LOADING -> placeholderRows(
                labels = listOf(
                    "Properties checked",
                    "Property hits",
                    "Reflection hits",
                    "getprop hits",
                    "JVM hits",
                    "Native prop hits",
                    "Native traces",
                    "Native library",
                ),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
            )

            PlayIntegrityFixStage.FAILED -> placeholderRows(
                labels = listOf(
                    "Properties checked",
                    "Property hits",
                    "Reflection hits",
                    "getprop hits",
                    "JVM hits",
                    "Native prop hits",
                    "Native traces",
                    "Native library",
                ),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
            )

            PlayIntegrityFixStage.READY -> listOf(
                PlayIntegrityFixDetailRowModel(
                    label = "Properties checked",
                    value = report.checkedPropertyCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                PlayIntegrityFixDetailRowModel(
                    label = "Property hits",
                    value = report.directPropertyCount.toString(),
                    status = propertyStatus(report),
                ),
                PlayIntegrityFixDetailRowModel(
                    label = "Reflection hits",
                    value = report.reflectionHitCount.toString(),
                    status = if (report.reflectionHitCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                PlayIntegrityFixDetailRowModel(
                    label = "getprop hits",
                    value = report.getpropHitCount.toString(),
                    status = if (report.getpropHitCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                PlayIntegrityFixDetailRowModel(
                    label = "JVM hits",
                    value = report.jvmHitCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                PlayIntegrityFixDetailRowModel(
                    label = "Native prop hits",
                    value = report.nativePropertyHitCount.toString(),
                    status = when {
                        report.nativePropertyHitCount > 0 -> DetectorStatus.warning()
                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                PlayIntegrityFixDetailRowModel(
                    label = "Native traces",
                    value = report.nativeTraceCount.toString(),
                    status = when {
                        report.nativeSignals.any { it.severity == PlayIntegrityFixSignalSeverity.DANGER } -> DetectorStatus.danger()
                        report.nativeTraceCount > 0 -> DetectorStatus.warning()
                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                PlayIntegrityFixDetailRowModel(
                    label = "Native library",
                    value = if (report.nativeAvailable) "Loaded" else "Unavailable",
                    status = if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
            )
        }
    }

    private fun signalRow(signal: PlayIntegrityFixSignal): PlayIntegrityFixDetailRowModel {
        val detailLines = buildList {
            add("Source: ${signal.source.label}")
            if (signal.group != PlayIntegrityFixGroup.NATIVE) {
                add("Category: ${signal.category.label}")
            }
            add(signal.detail)
        }
        return PlayIntegrityFixDetailRowModel(
            label = signal.label,
            value = badgeValue(signal.value),
            status = signalStatus(signal),
            detail = detailLines.joinToString(separator = "\n"),
            detailMonospace = signal.detailMonospace,
        )
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus,
    ): List<PlayIntegrityFixHeaderFactModel> {
        return listOf(
            PlayIntegrityFixHeaderFactModel("Direct", value, status),
            PlayIntegrityFixHeaderFactModel("Review", value, status),
            PlayIntegrityFixHeaderFactModel("Props", value, status),
            PlayIntegrityFixHeaderFactModel("Native", value, status),
        )
    }

    private fun placeholderRows(
        labels: List<String>,
        status: DetectorStatus,
        value: String,
        monospace: Boolean = false,
    ): List<PlayIntegrityFixDetailRowModel> {
        return labels.map { label ->
            PlayIntegrityFixDetailRowModel(
                label = label,
                value = value,
                status = status,
                detailMonospace = monospace,
            )
        }
    }

    private fun placeholderMethodRows(
        status: DetectorStatus,
        value: String,
    ): List<PlayIntegrityFixDetailRowModel> {
        return listOf(
            "Reflection API",
            "getprop snapshot",
            "JVM fallback",
            "Native libc props",
            "Native maps",
            "Property catalog",
            "Source consistency",
        ).map { label ->
            PlayIntegrityFixDetailRowModel(
                label = label,
                value = value,
                status = status,
            )
        }
    }

    private fun propertyStatus(report: PlayIntegrityFixReport): DetectorStatus {
        return when {
            report.propertySignals.any { it.severity == PlayIntegrityFixSignalSeverity.DANGER } -> DetectorStatus.danger()
            report.propertySignals.any { it.severity == PlayIntegrityFixSignalSeverity.WARNING } -> DetectorStatus.warning()
            else -> DetectorStatus.allClear()
        }
    }

    private fun nativeFactValue(report: PlayIntegrityFixReport): String {
        if (!report.nativeAvailable) {
            return "N/A"
        }
        val total = report.nativePropertyHitCount + report.nativeTraceCount
        return if (total > 0) total.toString() else "Clean"
    }

    private fun nativeFactStatus(report: PlayIntegrityFixReport): DetectorStatus {
        return when {
            report.nativeSignals.any { it.severity == PlayIntegrityFixSignalSeverity.DANGER } -> DetectorStatus.danger()
            report.nativePropertyHitCount > 0 || report.nativeSignals.isNotEmpty() -> DetectorStatus.warning()
            report.nativeAvailable -> DetectorStatus.allClear()
            else -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun countOrNone(count: Int): String {
        return if (count > 0) count.toString() else "None"
    }

    private fun countOrClean(count: Int): String {
        return if (count > 0) count.toString() else "Clean"
    }

    private fun badgeValue(value: String): String {
        return if (value.length > MAX_BADGE_LENGTH) {
            value.take(MAX_BADGE_LENGTH - 1) + "…"
        } else {
            value
        }
    }

    private fun signalStatus(signal: PlayIntegrityFixSignal): DetectorStatus {
        return when (signal.severity) {
            PlayIntegrityFixSignalSeverity.DANGER -> DetectorStatus.danger()
            PlayIntegrityFixSignalSeverity.WARNING -> DetectorStatus.warning()
        }
    }

    private fun methodStatus(result: PlayIntegrityFixMethodResult): DetectorStatus {
        return when (result.outcome) {
            PlayIntegrityFixMethodOutcome.CLEAN -> DetectorStatus.allClear()
            PlayIntegrityFixMethodOutcome.DETECTED -> DetectorStatus.danger()
            PlayIntegrityFixMethodOutcome.WARNING -> DetectorStatus.warning()
            PlayIntegrityFixMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun PlayIntegrityFixReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            PlayIntegrityFixStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            PlayIntegrityFixStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            PlayIntegrityFixStage.READY -> when {
                dangerSignalCount > 0 -> DetectorStatus.danger()
                warningSignalCount > 0 -> DetectorStatus.warning()
                else -> DetectorStatus.allClear()
            }
        }
    }

    companion object {
        private const val MAX_BADGE_LENGTH = 18
    }
}
