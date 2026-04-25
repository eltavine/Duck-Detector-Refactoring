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

package com.eltavine.duckdetector.features.kernelcheck.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckCvePatchState
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckFinding
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckMethodOutcome
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckMethodResult
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckReport
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckStage
import com.eltavine.duckdetector.features.kernelcheck.ui.model.KernelCheckCardModel
import com.eltavine.duckdetector.features.kernelcheck.ui.model.KernelCheckDetailRowModel
import com.eltavine.duckdetector.features.kernelcheck.ui.model.KernelCheckHeaderFactModel
import com.eltavine.duckdetector.features.kernelcheck.ui.model.KernelCheckImpactItemModel

class KernelCheckCardModelMapper {

    fun map(
        report: KernelCheckReport,
    ): KernelCheckCardModel {
        return KernelCheckCardModel(
            title = "Kernel Check",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            identityRows = buildIdentityRows(report),
            anomalyRows = buildAnomalyRows(report),
            behaviorRows = buildBehaviorRows(report),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }

    private fun buildSubtitle(report: KernelCheckReport): String {
        return when (report.stage) {
            KernelCheckStage.LOADING -> "uname + /proc/version + boot cmdline + CVE heuristic"
            KernelCheckStage.FAILED -> "local kernel probe failed"
            KernelCheckStage.READY -> {
                val nativeLabel =
                    if (report.nativeAvailable) "native /proc" else "fallback file reads"
                "${report.checkedKeywordCount} keyword families · ${report.checkedCmdlineRuleCount} cmdline rules · $nativeLabel"
            }
        }
    }

    private fun buildVerdict(report: KernelCheckReport): String {
        return when (report.stage) {
            KernelCheckStage.LOADING -> "Scanning kernel identity"
            KernelCheckStage.FAILED -> "Kernel Check scan failed"
            KernelCheckStage.READY -> when {
                report.hasHardIndicators -> "${report.hardFindingCount} suspicious kernel signal(s)"
                report.hasReviewInfoIndicators -> "Kernel behavior needs review"
                report.hasInformationalCveState -> "CVE patch state is informational"
                report.cvePatchState == KernelCheckCvePatchState.INCONCLUSIVE -> "CVE patch state inconclusive"
                !report.nativeAvailable -> "Kernel naming looks clean"
                else -> "No suspicious kernel markers"
            }
        }
    }

    private fun buildSummary(report: KernelCheckReport): String {
        return when (report.stage) {
            KernelCheckStage.LOADING ->
                "Kernel naming, boot parameter, build-time, pointer-exposure, and Unicode path-bypass heuristics are collecting local evidence."

            KernelCheckStage.FAILED ->
                report.errorMessage ?: "Kernel Check failed before evidence could be assembled."

            KernelCheckStage.READY -> when {
                report.hasHardIndicators ->
                    "Kernel identity text or boot-time native checks surfaced markers commonly seen on modified or community-built kernels."

                report.hasReviewInfoIndicators ->
                    "Kernel behavior heuristics surfaced review-worthy signals, but they are weaker than direct naming or boot parameter anomalies."

                report.hasInformationalCveState ->
                    "The Unicode path-bypass probe suggests CVE-2024-43093 is not fully patched, but this is informational context rather than a kernel-compromise signal."

                report.cvePatchState == KernelCheckCvePatchState.INCONCLUSIVE ->
                    "The Unicode path-bypass probe could not determine whether CVE-2024-43093 is fully patched on this device."

                !report.nativeAvailable ->
                    "Kernel naming stayed clean, but some native-only /proc checks were unavailable on this build."

                else ->
                    "Kernel identity, boot parameters, and behavior heuristics stayed within expected bounds."
            }
        }
    }

    private fun buildHeaderFacts(report: KernelCheckReport): List<KernelCheckHeaderFactModel> {
        return when (report.stage) {
            KernelCheckStage.LOADING -> placeholderFacts(
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            KernelCheckStage.FAILED -> placeholderFacts(
                "Error",
                DetectorStatus.info(InfoKind.ERROR)
            )

            KernelCheckStage.READY -> listOf(
                KernelCheckHeaderFactModel(
                    label = "Naming",
                    value = when {
                        report.namingFindingCount > 0 -> report.namingFindingCount.toString()
                        report.unameOutput.isBlank() && report.procVersion.isBlank() -> "N/A"
                        else -> "Clean"
                    },
                    status = when {
                        report.namingFindingCount > 0 -> DetectorStatus.danger()
                        report.unameOutput.isBlank() && report.procVersion.isBlank() -> DetectorStatus.info(
                            InfoKind.SUPPORT
                        )

                        else -> DetectorStatus.allClear()
                    },
                ),
                KernelCheckHeaderFactModel(
                    label = "Boot",
                    value = when {
                        report.bootFindingCount > 0 -> report.bootFindingCount.toString()
                        report.nativeAvailable || report.procCmdline.isNotBlank() || report.procVersion.isNotBlank() -> "Clean"
                        else -> "N/A"
                    },
                    status = when {
                        report.bootFindingCount > 0 -> DetectorStatus.danger()
                        report.nativeAvailable || report.procCmdline.isNotBlank() || report.procVersion.isNotBlank() -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                KernelCheckHeaderFactModel(
                    label = "Behavior",
                    value = when {
                        report.hasReviewInfoIndicators -> report.reviewInfoFindingCount.toString()
                        report.hasInformationalCveState -> report.cvePatchState.label
                        report.cvePatchState == KernelCheckCvePatchState.INCONCLUSIVE -> "Inconclusive"
                        report.nativeAvailable -> "OK"
                        else -> "Partial"
                    },
                    status = when {
                        report.hasReviewInfoIndicators -> DetectorStatus.warning()
                        report.hasInformationalCveState -> DetectorStatus.info(InfoKind.SUPPORT)
                        report.cvePatchState == KernelCheckCvePatchState.INCONCLUSIVE -> DetectorStatus.info(
                            InfoKind.SUPPORT
                        )

                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                KernelCheckHeaderFactModel(
                    label = "Native",
                    value = if (report.nativeAvailable) "Loaded" else "N/A",
                    status = if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
            )
        }
    }

    private fun buildIdentityRows(report: KernelCheckReport): List<KernelCheckDetailRowModel> {
        return when (report.stage) {
            KernelCheckStage.LOADING -> placeholderRows(
                labels = listOf("uname -a", "/proc/version", "/proc/cmdline"),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
                monospace = true,
            )

            KernelCheckStage.FAILED -> placeholderRows(
                labels = listOf("uname -a", "/proc/version", "/proc/cmdline"),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
                monospace = true,
            )

            KernelCheckStage.READY -> listOf(
                identityRow("uname -a", report.unameOutput),
                identityRow("/proc/version", report.procVersion),
                identityRow("/proc/cmdline", report.procCmdline),
            )
        }
    }

    private fun buildAnomalyRows(report: KernelCheckReport): List<KernelCheckDetailRowModel> {
        return when (report.stage) {
            KernelCheckStage.LOADING -> placeholderRows(
                labels = listOf("Kernel naming", "Boot parameters", "Build time"),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
            )

            KernelCheckStage.FAILED -> placeholderRows(
                labels = listOf("Kernel naming", "Boot parameters", "Build time"),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
            )

            KernelCheckStage.READY -> if (report.dangerFindings.isEmpty()) {
                listOf(
                    KernelCheckDetailRowModel(
                        label = "Anomalies",
                        value = "Clean",
                        status = DetectorStatus.allClear(),
                        detail = "No hard kernel naming or boot-time anomaly surfaced.",
                    ),
                )
            } else {
                report.dangerFindings.map(::findingRowDanger)
            }
        }
    }

    private fun buildBehaviorRows(report: KernelCheckReport): List<KernelCheckDetailRowModel> {
        return when (report.stage) {
            KernelCheckStage.LOADING -> placeholderRows(
                labels = listOf("CVE patch state", "kptr_restrict"),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
            )

            KernelCheckStage.FAILED -> placeholderRows(
                labels = listOf("CVE patch state", "kptr_restrict"),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
            )

            KernelCheckStage.READY -> listOf(
                cvePatchRow(report),
                kptrRow(report),
            )
        }
    }

    private fun buildImpactItems(report: KernelCheckReport): List<KernelCheckImpactItemModel> {
        return when (report.stage) {
            KernelCheckStage.LOADING -> listOf(
                KernelCheckImpactItemModel(
                    text = "Gathering local kernel evidence.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            KernelCheckStage.FAILED -> listOf(
                KernelCheckImpactItemModel(
                    text = report.errorMessage ?: "Kernel Check scan failed.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            KernelCheckStage.READY -> when {
                report.hasHardIndicators -> listOf(
                    KernelCheckImpactItemModel(
                        text = "Modified or community-built kernels can change trust posture, boot state, and device integrity behavior.",
                        status = DetectorStatus.danger(),
                    ),
                    KernelCheckImpactItemModel(
                        text = "These heuristics do not prove malicious compromise, but they do indicate the kernel differs from conservative stock expectations.",
                        status = DetectorStatus.warning(),
                    ),
                    KernelCheckImpactItemModel(
                        text = "Play Integrity, banking apps, or DRM-sensitive apps may react differently on such kernels.",
                        status = DetectorStatus.warning(),
                    ),
                )

                report.hasReviewInfoIndicators -> listOf(
                    KernelCheckImpactItemModel(
                        text = "Behavior-level signals are weaker than direct naming or boot parameter hits and should be interpreted with device context.",
                        status = DetectorStatus.warning(),
                    ),
                    KernelCheckImpactItemModel(
                        text = "A partial CVE patch or exposed kernel pointers can reflect aftermarket hardening gaps rather than active compromise.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )

                report.hasInformationalCveState -> listOf(
                    KernelCheckImpactItemModel(
                        text = "The CVE-2024-43093 probe suggests the path-filter fix is missing or incomplete, but this remains informational context rather than a root or tamper verdict.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                    KernelCheckImpactItemModel(
                        text = "This signal is useful for hardening posture, but it should not elevate the entire kernel card to warning on its own.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )

                report.cvePatchState == KernelCheckCvePatchState.INCONCLUSIVE -> listOf(
                    KernelCheckImpactItemModel(
                        text = "The CVE-2024-43093 probe was inconclusive, so this card cannot claim the path-filter fix is present.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                    KernelCheckImpactItemModel(
                        text = "An inconclusive result is weaker than a warning and can happen when direct Android/data listing behavior does not allow a clean bypass experiment.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )

                !report.nativeAvailable -> listOf(
                    KernelCheckImpactItemModel(
                        text = "Kernel naming checks were clean.",
                        status = DetectorStatus.allClear(),
                    ),
                    KernelCheckImpactItemModel(
                        text = "Native-only /proc checks were unavailable, so this result has reduced coverage.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )

                else -> listOf(
                    KernelCheckImpactItemModel(
                        text = "No suspicious naming, boot parameter, or behavior signal surfaced.",
                        status = DetectorStatus.allClear(),
                    ),
                    KernelCheckImpactItemModel(
                        text = "This remains heuristic evidence rather than proof of a fully stock device.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )
            }
        }
    }

    private fun buildMethodRows(report: KernelCheckReport): List<KernelCheckDetailRowModel> {
        return when (report.stage) {
            KernelCheckStage.LOADING -> placeholderMethodRows(
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending"
            )

            KernelCheckStage.FAILED -> placeholderMethodRows(
                DetectorStatus.info(InfoKind.ERROR),
                "Failed"
            )

            KernelCheckStage.READY -> report.methods.map { result ->
                KernelCheckDetailRowModel(
                    label = result.label,
                    value = result.summary,
                    status = methodStatus(result),
                    detail = result.detail,
                    detailMonospace = true,
                )
            }
        }
    }

    private fun buildScanRows(report: KernelCheckReport): List<KernelCheckDetailRowModel> {
        return when (report.stage) {
            KernelCheckStage.LOADING -> placeholderRows(
                labels = listOf(
                    "Keyword families checked",
                    "Cmdline rules checked",
                    "Hard findings",
                    "Info findings",
                    "Identity sources",
                    "Native library",
                ),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
            )

            KernelCheckStage.FAILED -> placeholderRows(
                labels = listOf(
                    "Keyword families checked",
                    "Cmdline rules checked",
                    "Hard findings",
                    "Info findings",
                    "Identity sources",
                    "Native library",
                ),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
            )

            KernelCheckStage.READY -> listOf(
                KernelCheckDetailRowModel(
                    label = "Keyword families checked",
                    value = report.checkedKeywordCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                KernelCheckDetailRowModel(
                    label = "Cmdline rules checked",
                    value = report.checkedCmdlineRuleCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                KernelCheckDetailRowModel(
                    label = "Hard findings",
                    value = report.hardFindingCount.toString(),
                    status = if (report.hardFindingCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                KernelCheckDetailRowModel(
                    label = "Info findings",
                    value = report.infoFindingCount.toString(),
                    status = when {
                        report.hasReviewInfoIndicators -> DetectorStatus.warning()
                        report.infoFindingCount > 0 -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.allClear()
                    },
                ),
                KernelCheckDetailRowModel(
                    label = "CVE patch state",
                    value = report.cvePatchState.label,
                    status = cvePatchStatus(report.cvePatchState),
                ),
                KernelCheckDetailRowModel(
                    label = "Identity sources",
                    value = identitySourceCount(report).toString(),
                    status = if (identitySourceCount(report) > 0) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                KernelCheckDetailRowModel(
                    label = "Native library",
                    value = if (report.nativeAvailable) "Loaded" else "Unavailable",
                    status = if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
            )
        }
    }

    private fun identityRow(
        label: String,
        value: String,
    ): KernelCheckDetailRowModel {
        return KernelCheckDetailRowModel(
            label = label,
            value = if (value.isNotBlank()) "Captured" else "Unavailable",
            status = if (value.isNotBlank()) DetectorStatus.allClear() else DetectorStatus.info(
                InfoKind.SUPPORT
            ),
            detail = value.ifBlank { "No readable data surfaced for $label." },
            detailMonospace = true,
        )
    }

    private fun findingRowDanger(
        finding: KernelCheckFinding,
    ): KernelCheckDetailRowModel {
        return KernelCheckDetailRowModel(
            label = finding.label,
            value = finding.value,
            status = DetectorStatus.danger(),
            detail = finding.detail,
            detailMonospace = true,
        )
    }

    private fun findingRowWarning(
        finding: KernelCheckFinding,
    ): KernelCheckDetailRowModel {
        return KernelCheckDetailRowModel(
            label = finding.label,
            value = finding.value,
            status = DetectorStatus.warning(),
            detail = finding.detail,
            detailMonospace = true,
        )
    }

    private fun cvePatchRow(
        report: KernelCheckReport,
    ): KernelCheckDetailRowModel {
        return KernelCheckDetailRowModel(
            label = "CVE-2024-43093",
            value = report.cvePatchState.label,
            status = cvePatchStatus(report.cvePatchState),
            detail = report.cvePatchDetail ?: when (report.cvePatchState) {
                KernelCheckCvePatchState.UNPATCHED ->
                    "Unicode ignorable codepoints still bypass the path filter."

                KernelCheckCvePatchState.PARTIALLY_PATCHED ->
                    "ZWC is blocked, but at least one other ignorable codepoint still bypasses the path filter."

                KernelCheckCvePatchState.PATCHED ->
                    "The tested bypass characters were blocked."

                KernelCheckCvePatchState.INCONCLUSIVE ->
                    "The probe could not determine a stable patch state."
            },
            detailMonospace = false,
        )
    }

    private fun kptrRow(
        report: KernelCheckReport,
    ): KernelCheckDetailRowModel {
        return when {
            report.kptrExposed -> {
                val finding = report.infoFindings.firstOrNull { it.id == "kptr_exposed" }
                KernelCheckDetailRowModel(
                    label = "kptr_restrict",
                    value = "Exposed",
                    status = DetectorStatus.warning(),
                    detail = finding?.detail ?: "kptr_restrict appears disabled.",
                )
            }

            report.nativeAvailable -> {
                KernelCheckDetailRowModel(
                    label = "kptr_restrict",
                    value = "Protected",
                    status = DetectorStatus.allClear(),
                    detail = "Kernel addresses remained hidden during the native probe.",
                )
            }

            else -> {
                KernelCheckDetailRowModel(
                    label = "kptr_restrict",
                    value = "Unavailable",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                    detail = "Native /proc coverage was unavailable, so pointer exposure could not be verified.",
                )
            }
        }
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus,
    ): List<KernelCheckHeaderFactModel> {
        return listOf(
            KernelCheckHeaderFactModel("Naming", value, status),
            KernelCheckHeaderFactModel("Boot", value, status),
            KernelCheckHeaderFactModel("Behavior", value, status),
            KernelCheckHeaderFactModel("Native", value, status),
        )
    }

    private fun placeholderRows(
        labels: List<String>,
        status: DetectorStatus,
        value: String,
        monospace: Boolean = false,
    ): List<KernelCheckDetailRowModel> {
        return labels.map { label ->
            KernelCheckDetailRowModel(
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
    ): List<KernelCheckDetailRowModel> {
        return listOf(
            "emojiScan",
            "chineseScan",
            "scriptScan",
            "telegramScan",
            "mentionScan",
            "customKernel",
            "cmdlineCheck",
            "buildTime",
            "cvePatchCheck",
            "kptrRestrict",
            "nativeLibrary",
        ).map { label ->
            KernelCheckDetailRowModel(
                label = label,
                value = value,
                status = status,
            )
        }
    }

    private fun identitySourceCount(report: KernelCheckReport): Int {
        return listOf(report.unameOutput, report.procVersion).count { it.isNotBlank() }
    }

    private fun cvePatchStatus(
        state: KernelCheckCvePatchState,
    ): DetectorStatus {
        return when (state) {
            KernelCheckCvePatchState.UNPATCHED,
            KernelCheckCvePatchState.PARTIALLY_PATCHED -> DetectorStatus.info(InfoKind.SUPPORT)

            KernelCheckCvePatchState.PATCHED -> DetectorStatus.allClear()
            KernelCheckCvePatchState.INCONCLUSIVE -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun methodStatus(result: KernelCheckMethodResult): DetectorStatus {
        return when (result.outcome) {
            KernelCheckMethodOutcome.CLEAN -> DetectorStatus.allClear()
            KernelCheckMethodOutcome.DETECTED -> DetectorStatus.danger()
            KernelCheckMethodOutcome.INFO -> {
                if (result.label == "cvePatchCheck") {
                    DetectorStatus.info(InfoKind.SUPPORT)
                } else {
                    DetectorStatus.warning()
                }
            }

            KernelCheckMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun KernelCheckReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            KernelCheckStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            KernelCheckStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            KernelCheckStage.READY -> when {
                hasHardIndicators -> DetectorStatus.danger()
                hasReviewInfoIndicators -> DetectorStatus.warning()
                hasInformationalCveState -> DetectorStatus.info(InfoKind.SUPPORT)
                cvePatchState == KernelCheckCvePatchState.INCONCLUSIVE -> DetectorStatus.info(
                    InfoKind.SUPPORT
                )

                !nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                else -> DetectorStatus.allClear()
            }
        }
    }
}
