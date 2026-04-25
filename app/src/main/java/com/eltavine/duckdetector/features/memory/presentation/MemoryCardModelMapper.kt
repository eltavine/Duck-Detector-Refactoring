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

package com.eltavine.duckdetector.features.memory.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.memory.domain.MemoryFinding
import com.eltavine.duckdetector.features.memory.domain.MemoryFindingSection
import com.eltavine.duckdetector.features.memory.domain.MemoryFindingSeverity
import com.eltavine.duckdetector.features.memory.domain.MemoryMethodOutcome
import com.eltavine.duckdetector.features.memory.domain.MemoryMethodResult
import com.eltavine.duckdetector.features.memory.domain.MemoryReport
import com.eltavine.duckdetector.features.memory.domain.MemoryStage
import com.eltavine.duckdetector.features.memory.ui.model.MemoryCardModel
import com.eltavine.duckdetector.features.memory.ui.model.MemoryDetailRowModel
import com.eltavine.duckdetector.features.memory.ui.model.MemoryHeaderFactModel
import com.eltavine.duckdetector.features.memory.ui.model.MemoryImpactItemModel

class MemoryCardModelMapper {

    fun map(report: MemoryReport): MemoryCardModel {
        return MemoryCardModel(
            title = "Memory",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            hookRows = buildSectionRows(report, setOf(MemoryFindingSection.HOOK), "Function hooks"),
            mappingRows = buildSectionRows(
                report,
                setOf(MemoryFindingSection.MAPS, MemoryFindingSection.FD),
                "Mappings"
            ),
            loaderRows = buildSectionRows(
                report,
                setOf(
                    MemoryFindingSection.SIGNAL,
                    MemoryFindingSection.VDSO,
                    MemoryFindingSection.LINKER
                ),
                "Loader visibility"
            ),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }

    private fun buildSubtitle(report: MemoryReport): String {
        return when (report.stage) {
            MemoryStage.LOADING -> "function entry + maps/smaps + fd + signal + linker"
            MemoryStage.FAILED -> "local native probe failed"
            MemoryStage.READY -> "6 native detector families · current-process memory only"
        }
    }

    private fun buildVerdict(report: MemoryReport): String {
        return when (report.stage) {
            MemoryStage.LOADING -> "Scanning runtime memory"
            MemoryStage.FAILED -> "Memory scan failed"
            MemoryStage.READY -> when {
                report.dangerFindingCount > 0 -> "${report.dangerFindingCount} high-risk memory signal(s)"
                report.reviewFindingCount > 0 -> "Runtime memory needs review"
                else -> "No hook-like memory signals"
            }
        }
    }

    private fun buildSummary(report: MemoryReport): String {
        return when (report.stage) {
            MemoryStage.LOADING ->
                "This detector checks symbol resolution, function entry bytes, executable mappings, suspicious memfd or deleted libraries, signal handlers, and loader visibility."

            MemoryStage.FAILED ->
                report.errorMessage
                    ?: "Memory detection failed before native evidence could be assembled."

            MemoryStage.READY -> when {
                report.dangerFindingCount > 0 ->
                    "High-risk findings point to hook-like code redirection, suspicious executable mappings, or loader-visible runtime artifacts."

                report.reviewFindingCount > 0 ->
                    "The current process memory stayed mostly clean, but there are still runtime indicators that deserve review."

                else ->
                    "No hook-style prologue changes, suspicious executable memfd paths, or loader visibility mismatches surfaced."
            }
        }
    }

    private fun buildHeaderFacts(report: MemoryReport): List<MemoryHeaderFactModel> {
        return when (report.stage) {
            MemoryStage.LOADING -> placeholderFacts(
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            MemoryStage.FAILED -> placeholderFacts("Error", DetectorStatus.info(InfoKind.ERROR))
            MemoryStage.READY -> listOf(
                MemoryHeaderFactModel(
                    label = "Critical",
                    value = if (report.dangerFindingCount > 0) report.dangerFindingCount.toString() else "Clean",
                    status = if (report.dangerFindingCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                MemoryHeaderFactModel(
                    label = "Review",
                    value = if (report.reviewFindingCount > 0) report.reviewFindingCount.toString() else "Clean",
                    status = if (report.reviewFindingCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
                ),
                MemoryHeaderFactModel(
                    label = "Hooks",
                    value = when {
                        report.hookFindingCount > 0 -> report.hookFindingCount.toString()
                        report.modifiedFunctionCount > 0 -> report.modifiedFunctionCount.toString()
                        else -> "Clean"
                    },
                    status = when {
                        report.hookFindingCount > 0 -> DetectorStatus.danger()
                        report.modifiedFunctionCount > 0 -> DetectorStatus.warning()
                        else -> DetectorStatus.allClear()
                    },
                ),
                MemoryHeaderFactModel(
                    label = "Runtime",
                    value = when {
                        report.mappingFindingCount + report.loaderFindingCount > 0 ->
                            (report.mappingFindingCount + report.loaderFindingCount).toString()

                        else -> "Clean"
                    },
                    status = when {
                        report.mappingFindingCount + report.loaderFindingCount > 0 -> report.toDetectorStatus()
                        else -> DetectorStatus.allClear()
                    },
                ),
            )
        }
    }

    private fun buildSectionRows(
        report: MemoryReport,
        sections: Set<MemoryFindingSection>,
        fallbackLabel: String,
    ): List<MemoryDetailRowModel> {
        return when (report.stage) {
            MemoryStage.LOADING -> placeholderRows(
                listOf(fallbackLabel),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending"
            )

            MemoryStage.FAILED -> placeholderRows(
                listOf(fallbackLabel),
                DetectorStatus.info(InfoKind.ERROR),
                "Error"
            )

            MemoryStage.READY -> {
                val rows = report.findings
                    .filter { it.section in sections }
                    .map(::findingRow)
                if (rows.isNotEmpty()) {
                    rows
                } else {
                    listOf(
                        MemoryDetailRowModel(
                            label = fallbackLabel,
                            value = "Clean",
                            status = DetectorStatus.allClear(),
                            detail = "No suspicious evidence surfaced in this memory slice.",
                        ),
                    )
                }
            }
        }
    }

    private fun buildImpactItems(report: MemoryReport): List<MemoryImpactItemModel> {
        return when (report.stage) {
            MemoryStage.LOADING -> listOf(
                MemoryImpactItemModel(
                    text = "Gathering local runtime memory evidence.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            MemoryStage.FAILED -> listOf(
                MemoryImpactItemModel(
                    text = report.errorMessage ?: "Memory scan failed.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            MemoryStage.READY -> when {
                report.dangerFindingCount > 0 -> listOf(
                    MemoryImpactItemModel(
                        text = "Hook-like entry changes, deleted executable loaders, or anonymous signal handlers are stronger runtime tampering signals than filesystem-only artifacts.",
                        status = DetectorStatus.danger(),
                    ),
                    MemoryImpactItemModel(
                        text = "This card only sees the current app process, so it should be read together with mount, SU, kernel, and TEE evidence.",
                        status = DetectorStatus.warning(),
                    ),
                )

                report.reviewFindingCount > 0 -> listOf(
                    MemoryImpactItemModel(
                        text = "The findings here are weaker than a direct hook or deleted loader hit, but they still mean the runtime view is not fully boring.",
                        status = DetectorStatus.warning(),
                    ),
                    MemoryImpactItemModel(
                        text = "Review findings often come from mapping hygiene, loader visibility, or vDSO consistency rather than a direct redirection primitive.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )

                else -> listOf(
                    MemoryImpactItemModel(
                        text = "The current process did not expose branch-heavy function entries, suspicious executable memfd paths, or loader visibility mismatches.",
                        status = DetectorStatus.allClear(),
                    ),
                    MemoryImpactItemModel(
                        text = "A clean result reduces the chance of in-process runtime hooking, but it does not prove the whole device is stock.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )
            }
        }
    }

    private fun buildMethodRows(report: MemoryReport): List<MemoryDetailRowModel> {
        return when (report.stage) {
            MemoryStage.LOADING -> placeholderRows(
                listOf(
                    "GOT/PLT resolution",
                    "Entry prologue",
                    "maps + smaps",
                    "FD-backed code",
                    "Signal handlers",
                    "Loader visibility"
                ),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending",
            )

            MemoryStage.FAILED -> placeholderRows(
                listOf(
                    "GOT/PLT resolution",
                    "Entry prologue",
                    "maps + smaps",
                    "FD-backed code",
                    "Signal handlers",
                    "Loader visibility"
                ),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
            )

            MemoryStage.READY -> report.methods.map { method ->
                MemoryDetailRowModel(
                    label = method.label,
                    value = method.summary,
                    status = methodStatus(method),
                    detail = method.detail,
                )
            }
        }
    }

    private fun buildScanRows(report: MemoryReport): List<MemoryDetailRowModel> {
        return when (report.stage) {
            MemoryStage.LOADING -> placeholderRows(
                listOf(
                    "Danger findings",
                    "Review findings",
                    "Modified functions",
                    "Native library"
                ),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending",
            )

            MemoryStage.FAILED -> placeholderRows(
                listOf(
                    "Danger findings",
                    "Review findings",
                    "Modified functions",
                    "Native library"
                ),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
            )

            MemoryStage.READY -> listOf(
                MemoryDetailRowModel(
                    label = "Danger findings",
                    value = report.dangerFindingCount.toString(),
                    status = if (report.dangerFindingCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                MemoryDetailRowModel(
                    label = "Review findings",
                    value = report.reviewFindingCount.toString(),
                    status = if (report.reviewFindingCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
                ),
                MemoryDetailRowModel(
                    label = "Modified functions",
                    value = report.modifiedFunctionCount.toString(),
                    status = if (report.modifiedFunctionCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
                ),
                MemoryDetailRowModel(
                    label = "Native library",
                    value = if (report.nativeAvailable) "Loaded" else "Unavailable",
                    status = if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.ERROR
                    ),
                ),
            )
        }
    }

    private fun findingRow(finding: MemoryFinding): MemoryDetailRowModel {
        return MemoryDetailRowModel(
            label = finding.label,
            value = finding.severity.label,
            status = when (finding.severity) {
                MemoryFindingSeverity.CRITICAL,
                MemoryFindingSeverity.HIGH -> DetectorStatus.danger()

                MemoryFindingSeverity.MEDIUM -> DetectorStatus.warning()
                MemoryFindingSeverity.LOW -> DetectorStatus.info(InfoKind.SUPPORT)
            },
            detail = finding.detail,
            detailMonospace = finding.detailMonospace,
        )
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus,
    ): List<MemoryHeaderFactModel> {
        return listOf(
            MemoryHeaderFactModel("Critical", value, status),
            MemoryHeaderFactModel("Review", value, status),
            MemoryHeaderFactModel("Hooks", value, status),
            MemoryHeaderFactModel("Runtime", value, status),
        )
    }

    private fun placeholderRows(
        labels: List<String>,
        status: DetectorStatus,
        value: String,
    ): List<MemoryDetailRowModel> {
        return labels.map { label ->
            MemoryDetailRowModel(
                label = label,
                value = value,
                status = status,
            )
        }
    }

    private fun methodStatus(method: MemoryMethodResult): DetectorStatus {
        return when (method.outcome) {
            MemoryMethodOutcome.CLEAN -> DetectorStatus.allClear()
            MemoryMethodOutcome.REVIEW -> DetectorStatus.warning()
            MemoryMethodOutcome.DETECTED -> DetectorStatus.danger()
            MemoryMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun MemoryReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            MemoryStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            MemoryStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            MemoryStage.READY -> when {
                dangerFindingCount > 0 -> DetectorStatus.danger()
                reviewFindingCount > 0 -> DetectorStatus.warning()
                else -> DetectorStatus.allClear()
            }
        }
    }
}
