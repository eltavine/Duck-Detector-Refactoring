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

package com.eltavine.duckdetector.features.zygisk.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskMethod
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskMethodOutcome
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskMethodResult
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskReport
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskStage
import com.eltavine.duckdetector.features.zygisk.domain.toDetectorStatus
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskCardModel
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskDetailRowModel
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskHeaderFact
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskHeaderFactModel

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
            ZygiskStage.LOADING -> "cross-process fd trap + linker/maps/heap/runtime"
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
                "The detector is collecting cross-process specialization evidence first, then correlating environment, linker, namespace, maps, smaps, thread, fd, and heap traces from the current process."

            ZygiskStage.FAILED ->
                report.errorMessage ?: "Zygisk detection failed before evidence could be assembled."

            ZygiskStage.READY -> when (report.toDetectorStatus()) {
                DetectorStatus.danger() ->
                    "FD trap or direct runtime probes exposed evidence consistent with TMP_PATH leakage, specialization tampering, namespace bypass, linker redirection, ptrace attachment, or libc-hook side effects."

                DetectorStatus.warning() ->
                    "Only heuristic residue surfaced, so this result should be read together with Memory and Mount before treating it as a confirmed Zygisk runtime."

                DetectorStatus.allClear() ->
                    "The FD trap stayed clean and the native runtime snapshot did not expose TMP_PATH, linker, maps, heap, thread, or descriptor traces associated with Zygisk-style injection."

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
                    fact = ZygiskHeaderFact.STATE,
                    value = stateLabel(report),
                    status = report.toDetectorStatus(),
                ),
                ZygiskHeaderFactModel(
                    fact = ZygiskHeaderFact.CONFIDENCE,
                    value = confidenceLabel(report),
                    status = confidenceStatus(report),
                ),
                ZygiskHeaderFactModel(
                    fact = ZygiskHeaderFact.FD_TRAP,
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
                    fact = ZygiskHeaderFact.NATIVE,
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
                    detail = "Direct strong signals include FD trap, NeoZygisk TMP_PATH leakage, namespace bypass, linker hook, and TracerPid positives.",
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

    private fun buildMethodRows(
        report: ZygiskReport,
    ): List<ZygiskDetailRowModel> {
        return when (report.stage) {
            ZygiskStage.LOADING -> placeholderMethodRows(DetectorStatus.info(InfoKind.SUPPORT), "Pending")

            ZygiskStage.FAILED -> placeholderMethodRows(DetectorStatus.info(InfoKind.ERROR), "Error")

            ZygiskStage.READY -> report.methods.map { method ->
                ZygiskDetailRowModel(
                    label = method.label,
                    value = method.summary,
                    status = methodStatus(method),
                    detail = method.detail,
                    detailMonospace = false,
                    icon = method.method.rowIcon(),
                )
            }
        }
    }

    private fun placeholderMethodRows(
        status: DetectorStatus,
        value: String,
    ): List<ZygiskDetailRowModel> {
        return ZygiskMethod.entries.map { method ->
            ZygiskDetailRowModel(label = method.label, value = value, status = status, icon = method.rowIcon())
        }
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus,
    ): List<ZygiskHeaderFactModel> {
        return listOf(
            ZygiskHeaderFactModel(ZygiskHeaderFact.STATE, value, status),
            ZygiskHeaderFactModel(ZygiskHeaderFact.CONFIDENCE, value, status),
            ZygiskHeaderFactModel(ZygiskHeaderFact.FD_TRAP, value, status),
            ZygiskHeaderFactModel(ZygiskHeaderFact.NATIVE, value, status),
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
            DetectorStatus.allClear() -> "Clear"
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

}
