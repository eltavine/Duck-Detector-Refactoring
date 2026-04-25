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
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskMethodOutcome
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskMethodResult
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskReport
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskSignal
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskSignalSeverity
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskStage
import com.eltavine.duckdetector.features.zygisk.ui.model.ZygiskCardModel
import com.eltavine.duckdetector.features.zygisk.ui.model.ZygiskDetailRowModel
import com.eltavine.duckdetector.features.zygisk.ui.model.ZygiskHeaderFactModel
import com.eltavine.duckdetector.features.zygisk.ui.model.ZygiskImpactItemModel

class ZygiskCardModelMapper {

    fun map(
        report: ZygiskReport,
    ): ZygiskCardModel {
        return ZygiskCardModel(
            title = "Zygisk",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            stateRows = buildStateRows(report),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            signalRows = buildSignalRows(report),
            references = report.references,
        )
    }

    private fun buildSubtitle(
        report: ZygiskReport,
    ): String {
        return when (report.stage) {
            ZygiskStage.LOADING -> "cross-process fd trap + linker/maps/heap/seccomp/runtime"
            ZygiskStage.FAILED -> "zygote injection scan failed"
            ZygiskStage.READY -> "${report.strongHitCount} strong · ${report.heuristicHitCount} heuristic · ${report.signals.size} signal(s)"
        }
    }

    private fun buildVerdict(
        report: ZygiskReport,
    ): String {
        return when (report.stage) {
            ZygiskStage.LOADING -> "Scanning Zygisk runtime traces"
            ZygiskStage.FAILED -> "Zygisk scan failed"
            ZygiskStage.READY -> when {
                report.fdTrapDetected -> "Cross-process FD trap is positive"
                report.nativeStrongHitCount > 0 -> "${report.nativeStrongHitCount} direct runtime signal(s)"
                report.heuristicHitCount >= 2 -> "${report.heuristicHitCount} heuristic probes converged"
                report.heuristicHitCount == 1 -> "One heuristic probe needs review"
                report.fullyClean -> "No Zygisk runtime signal"
                else -> "Zygisk result needs more support"
            }
        }
    }

    private fun buildSummary(
        report: ZygiskReport,
    ): String {
        return when (report.stage) {
            ZygiskStage.LOADING ->
                "The detector is collecting cross-process specialization evidence first, then correlating linker, namespace, maps, smaps, thread, fd, stack, seccomp, and heap traces from the current process."

            ZygiskStage.FAILED ->
                report.errorMessage ?: "Zygisk detection failed before evidence could be assembled."

            ZygiskStage.READY -> when (report.toDetectorStatus()) {
                DetectorStatus.danger() ->
                    "FD trap or direct runtime probes exposed evidence consistent with specialization tampering, namespace bypass, linker redirection, ptrace attachment, or libc-hook side effects."

                DetectorStatus.warning() ->
                    "Only heuristic residue surfaced, so this result should be read together with Memory and Mount before treating it as a confirmed Zygisk runtime."

                DetectorStatus.allClear() ->
                    "The FD trap stayed clean and the native runtime snapshot did not expose linker, maps, heap, thread, or descriptor traces associated with Zygisk-style injection."

                else ->
                    "One or more major scan paths were unavailable, so this card cannot treat the absence of hits as a clean runtime result."
            }
        }
    }

    private fun buildHeaderFacts(
        report: ZygiskReport,
    ): List<ZygiskHeaderFactModel> {
        return when (report.stage) {
            ZygiskStage.LOADING -> placeholderFacts(
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            ZygiskStage.FAILED -> placeholderFacts("Error", DetectorStatus.info(InfoKind.ERROR))
            ZygiskStage.READY -> listOf(
                ZygiskHeaderFactModel(
                    label = "State",
                    value = stateLabel(report),
                    status = report.toDetectorStatus(),
                ),
                ZygiskHeaderFactModel(
                    label = "Confidence",
                    value = confidenceLabel(report),
                    status = confidenceStatus(report),
                ),
                ZygiskHeaderFactModel(
                    label = "FD trap",
                    value = when {
                        report.fdTrapDetected -> "Detected"
                        report.fdTrapAvailable -> "Clean"
                        else -> "Unavailable"
                    },
                    status = when {
                        report.fdTrapDetected -> DetectorStatus.danger()
                        report.fdTrapAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                ZygiskHeaderFactModel(
                    label = "Native",
                    value = when {
                        report.nativeAvailable -> "Ready"
                        else -> "Unavailable"
                    },
                    status = when {
                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
            )
        }
    }

    private fun buildStateRows(
        report: ZygiskReport,
    ): List<ZygiskDetailRowModel> {
        return when (report.stage) {
            ZygiskStage.LOADING -> placeholderRows(
                listOf("State", "Confidence", "Strong signals", "Heuristic signals"),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending",
            )

            ZygiskStage.FAILED -> placeholderRows(
                listOf("State", "Confidence", "Strong signals", "Heuristic signals"),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
            )

            ZygiskStage.READY -> listOf(
                ZygiskDetailRowModel(
                    label = "State",
                    value = stateLabel(report),
                    status = report.toDetectorStatus(),
                    detail = "Balanced policy: FD trap or any direct runtime strong hit is red, one heuristic-only family is yellow, converging heuristic families also escalate to red.",
                ),
                ZygiskDetailRowModel(
                    label = "Confidence",
                    value = confidenceLabel(report),
                    status = confidenceStatus(report),
                    detail = when {
                        report.fdTrapDetected || report.nativeStrongHitCount > 0 -> "Independent runtime or cross-process evidence is present."
                        report.heuristicHitCount > 0 -> "Only weaker corroboration probes fired."
                        report.fullyClean -> "Both major paths completed without positive evidence."
                        else -> "A major scan path was unavailable, so the result is not treated as clean."
                    },
                ),
                ZygiskDetailRowModel(
                    label = "Strong signals",
                    value = report.strongHitCount.toString(),
                    status = if (report.strongHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                    detail = "Direct strong signals include FD trap, namespace bypass, linker hook, TracerPid, and seccomp trap positives.",
                ),
                ZygiskDetailRowModel(
                    label = "Heuristic signals",
                    value = report.heuristicHitCount.toString(),
                    status = when {
                        report.heuristicHitCount >= 2 -> DetectorStatus.danger()
                        report.heuristicHitCount == 1 -> DetectorStatus.warning()
                        else -> DetectorStatus.allClear()
                    },
                    detail = "Heuristic probes cover solist drift, maps and smaps anomalies, atexit routing, stack residue, suspicious threads or fds, and heap entropy.",
                ),
            )
        }
    }

    private fun buildImpactItems(
        report: ZygiskReport,
    ): List<ZygiskImpactItemModel> {
        return when (report.stage) {
            ZygiskStage.LOADING -> listOf(
                ZygiskImpactItemModel(
                    text = "Collecting the cross-process FD trap result and the native runtime snapshot in parallel.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            ZygiskStage.FAILED -> listOf(
                ZygiskImpactItemModel(
                    text = report.errorMessage ?: "Zygisk detection failed.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            ZygiskStage.READY -> when (report.toDetectorStatus()) {
                DetectorStatus.danger() -> listOf(
                    ZygiskImpactItemModel(
                        text = "A red result means this process exposed direct runtime evidence or the cross-process specialization path behaved like a Zygisk-sanitized child process.",
                        status = DetectorStatus.danger(),
                    ),
                    ZygiskImpactItemModel(
                        text = "This is stronger than package residue because it touches live loader behavior, specialization side effects, or process runtime state directly.",
                        status = DetectorStatus.warning(),
                    ),
                )

                DetectorStatus.warning() -> listOf(
                    ZygiskImpactItemModel(
                        text = "Yellow means only weaker corroboration traces were found, not a single decisive runtime primitive on their own.",
                        status = DetectorStatus.warning(),
                    ),
                    ZygiskImpactItemModel(
                        text = "Read this together with Memory and Mount, which can still surface loader and mapping residue in parallel.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )

                DetectorStatus.allClear() -> listOf(
                    ZygiskImpactItemModel(
                        text = "No direct runtime or converging heuristic signal surfaced in the current app process.",
                        status = DetectorStatus.allClear(),
                    ),
                    ZygiskImpactItemModel(
                        text = "A clean result reduces confidence in active Zygisk-style tampering for this process, but it does not prove the whole device is stock.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )

                else -> listOf(
                    ZygiskImpactItemModel(
                        text = "The detector completed, but at least one major path was unavailable, so this result is support-only rather than clean.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                    ZygiskImpactItemModel(
                        text = "Unavailable service binding, unsupported seccomp or heap helpers, or a missing native snapshot can all reduce confidence without implying a positive detection.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )
            }
        }
    }

    private fun buildMethodRows(
        report: ZygiskReport,
    ): List<ZygiskDetailRowModel> {
        return when (report.stage) {
            ZygiskStage.LOADING -> placeholderRows(
                listOf(
                    "Cross-process FD trap",
                    "Native snapshot",
                    "Seccomp syscall trap",
                    "Linker and namespace",
                    "Maps and smaps",
                    "Threads and FDs",
                    "Solist, atexit, stack, heap",
                ),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending",
            )

            ZygiskStage.FAILED -> placeholderRows(
                listOf(
                    "Cross-process FD trap",
                    "Native snapshot",
                    "Seccomp syscall trap",
                    "Linker and namespace",
                    "Maps and smaps",
                    "Threads and FDs",
                    "Solist, atexit, stack, heap",
                ),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
            )

            ZygiskStage.READY -> report.methods.map { method ->
                ZygiskDetailRowModel(
                    label = method.label,
                    value = method.summary,
                    status = methodStatus(method),
                    detail = method.detail,
                    detailMonospace = false,
                )
            }
        }
    }

    private fun buildSignalRows(
        report: ZygiskReport,
    ): List<ZygiskDetailRowModel> {
        return when (report.stage) {
            ZygiskStage.LOADING -> placeholderRows(
                listOf("Cross-process", "Runtime", "Linker", "Maps", "Heap", "Threads", "FDs"),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending",
            )

            ZygiskStage.FAILED -> placeholderRows(
                listOf("Cross-process", "Runtime", "Linker", "Maps", "Heap", "Threads", "FDs"),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
            )

            ZygiskStage.READY -> {
                if (report.signals.isEmpty()) {
                    listOf(
                        ZygiskDetailRowModel(
                            label = "Signals",
                            value = if (report.fullyClean) "Clean" else "Unavailable",
                            status = if (report.fullyClean) {
                                DetectorStatus.allClear()
                            } else {
                                DetectorStatus.info(InfoKind.SUPPORT)
                            },
                            detail = if (report.fullyClean) {
                                "No positive runtime signal surfaced in the current process."
                            } else {
                                "No positive signal surfaced, but a major scan path was unavailable so the result is support-only."
                            },
                        ),
                    )
                } else {
                    report.signals.map(::signalRow)
                }
            }
        }
    }

    private fun signalRow(
        signal: ZygiskSignal,
    ): ZygiskDetailRowModel {
        return ZygiskDetailRowModel(
            label = signal.label,
            value = signal.value,
            status = when (signal.severity) {
                ZygiskSignalSeverity.DANGER -> DetectorStatus.danger()
                ZygiskSignalSeverity.WARNING -> DetectorStatus.warning()
            },
            detail = signal.detail,
            detailMonospace = signal.detailMonospace,
        )
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus,
    ): List<ZygiskHeaderFactModel> {
        return listOf(
            ZygiskHeaderFactModel("State", value, status),
            ZygiskHeaderFactModel("Confidence", value, status),
            ZygiskHeaderFactModel("FD trap", value, status),
            ZygiskHeaderFactModel("Native", value, status),
        )
    }

    private fun placeholderRows(
        labels: List<String>,
        status: DetectorStatus,
        value: String,
    ): List<ZygiskDetailRowModel> {
        return labels.map { label ->
            ZygiskDetailRowModel(
                label = label,
                value = value,
                status = status,
            )
        }
    }

    private fun methodStatus(
        method: ZygiskMethodResult,
    ): DetectorStatus {
        return when (method.outcome) {
            ZygiskMethodOutcome.CLEAN -> DetectorStatus.allClear()
            ZygiskMethodOutcome.WARNING -> DetectorStatus.warning()
            ZygiskMethodOutcome.DETECTED -> DetectorStatus.danger()
            ZygiskMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun stateLabel(
        report: ZygiskReport,
    ): String {
        return when (report.toDetectorStatus()) {
            DetectorStatus.danger() -> "Danger"
            DetectorStatus.warning() -> "Warning"
            DetectorStatus.allClear() -> "All clear"
            else -> "Support"
        }
    }

    private fun confidenceLabel(
        report: ZygiskReport,
    ): String {
        return when {
            report.fdTrapDetected || report.nativeStrongHitCount > 0 -> "High"
            report.heuristicHitCount > 0 -> "Medium"
            report.fullyClean -> "High"
            else -> "Partial"
        }
    }

    private fun confidenceStatus(
        report: ZygiskReport,
    ): DetectorStatus {
        return when {
            report.fdTrapDetected || report.nativeStrongHitCount > 0 -> DetectorStatus.danger()
            report.heuristicHitCount > 0 -> DetectorStatus.warning()
            report.fullyClean -> DetectorStatus.allClear()
            else -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun ZygiskReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            ZygiskStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            ZygiskStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            ZygiskStage.READY -> when {
                fdTrapDetected -> DetectorStatus.danger()
                nativeStrongHitCount > 0 -> DetectorStatus.danger()
                heuristicHitCount >= 2 -> DetectorStatus.danger()
                heuristicHitCount == 1 -> DetectorStatus.warning()
                fullyClean -> DetectorStatus.allClear()
                else -> DetectorStatus.info(InfoKind.SUPPORT)
            }
        }
    }
}
