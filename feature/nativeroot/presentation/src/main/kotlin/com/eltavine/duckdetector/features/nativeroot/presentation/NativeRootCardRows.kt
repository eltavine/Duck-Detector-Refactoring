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

package com.eltavine.duckdetector.features.nativeroot.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethod
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodOutcome
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodResult
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootStage
import com.eltavine.duckdetector.features.nativeroot.presentation.model.NativeRootDetailRowModel

internal fun buildNativeRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
    return when (report.stage) {
        NativeRootStage.LOADING -> placeholderRows(
            listOf("KSU supercall", "KernelSU prctl", "SUSFS side-channel"),
            DetectorStatus.info(InfoKind.SUPPORT),
            "Pending",
        )

        NativeRootStage.FAILED -> placeholderRows(
            listOf("KSU supercall", "KernelSU prctl", "SUSFS side-channel"),
            DetectorStatus.info(InfoKind.ERROR),
            "Error",
        )

        NativeRootStage.READY -> buildList {
            addAll(report.directFindings.sortedBy { it.label }.map(::findingRow))
            if (report.ksuSupercallBlocked) {
                add(
                    NativeRootDetailRowModel(
                        label = "KSU supercall",
                        value = "Blocked by seccomp",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                        detail = "The sacrificial reboot() helper died under app seccomp before it could install a temporary [ksu_driver] fd. Other KernelSU checks still ran.",
                    )
                )
            }
        }
    }
}

internal fun buildRuntimeRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
    return when (report.stage) {
        NativeRootStage.LOADING -> placeholderRows(
            listOf(
                "Self process IOC",
                "Isolated mount drift",
                "Throne hunt",
                "Manager fingerprint",
                "Runtime paths",
                "Root processes",
                "Cgroup leakage",
            ),
            DetectorStatus.info(InfoKind.SUPPORT),
            "Pending",
        )

        NativeRootStage.FAILED -> placeholderRows(
            listOf(
                "Self process IOC",
                "Isolated mount drift",
                "Throne hunt",
                "Manager fingerprint",
                "Runtime paths",
                "Root processes",
                "Cgroup leakage",
            ),
            DetectorStatus.info(InfoKind.ERROR),
            "Error",
        )

        NativeRootStage.READY -> report.runtimeFindings.sortedBy { it.label }.map(::findingRow)
    }
}

internal fun buildKernelRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
    return when (report.stage) {
        NativeRootStage.LOADING -> placeholderRows(
            listOf("Kernel symbols", "Kernel modules", "Kernel identity"),
            DetectorStatus.info(InfoKind.SUPPORT),
            "Pending",
        )

        NativeRootStage.FAILED -> placeholderRows(
            listOf("Kernel symbols", "Kernel modules", "Kernel identity"),
            DetectorStatus.info(InfoKind.ERROR),
            "Error",
        )

        NativeRootStage.READY -> report.kernelFindings.sortedBy { it.label }.map(::findingRow)
    }
}

internal fun buildPropertyRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
    return when (report.stage) {
        NativeRootStage.LOADING -> placeholderRows(
            listOf("Root-specific properties"),
            DetectorStatus.info(InfoKind.SUPPORT),
            "Pending",
            monospace = true,
        )

        NativeRootStage.FAILED -> placeholderRows(
            listOf("Root-specific properties"),
            DetectorStatus.info(InfoKind.ERROR),
            "Error",
            monospace = true,
        )

        NativeRootStage.READY -> report.propertyFindings.sortedBy { it.label }.map(::findingRow)
    }
}

private fun findingRow(finding: NativeRootFinding): NativeRootDetailRowModel {
    return NativeRootDetailRowModel(
        label = finding.label,
        value = finding.value,
        status = findingStatus(finding),
        detail = finding.detail,
        detailMonospace = finding.detailMonospace,
    )
}

private fun findingStatus(finding: NativeRootFinding): DetectorStatus {
    return when (finding.severity) {
        NativeRootFindingSeverity.DANGER -> DetectorStatus.danger()
        NativeRootFindingSeverity.WARNING -> DetectorStatus.warning()
        NativeRootFindingSeverity.INFO -> DetectorStatus.info(InfoKind.SUPPORT)
    }
}

internal fun placeholderRows(
    labels: List<String>,
    status: DetectorStatus,
    value: String,
    monospace: Boolean = false,
): List<NativeRootDetailRowModel> {
    return labels.map { label ->
        NativeRootDetailRowModel(
            label = label,
            value = value,
            status = status,
            detailMonospace = monospace,
        )
    }
}

internal fun buildMethodRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
    return when (report.stage) {
        NativeRootStage.LOADING -> placeholderMethodRows(
            DetectorStatus.info(InfoKind.SUPPORT),
            "Pending"
        )

        NativeRootStage.FAILED -> placeholderMethodRows(
            DetectorStatus.info(InfoKind.ERROR),
            "Failed"
        )

        NativeRootStage.READY -> report.methods.map { result ->
            NativeRootDetailRowModel(
                label = result.label,
                value = result.summary,
                status = methodStatus(result),
                detail = result.detail,
                hiddenCopyText = if (result.method == NativeRootMethod.KSU_THRONE_HUNT) {
                    buildThroneHuntDiagnostics(report)
                } else {
                    null
                },
                detailMonospace = true,
            )
        } + srcuTimingRow(report.srcuTiming)
    }
}

private fun placeholderMethodRows(
    status: DetectorStatus,
    value: String,
): List<NativeRootDetailRowModel> {
    return listOf(
        "ksuReadonlySupercall",
        "prctlProbe",
        "susfsSideChannel",
        "selfProcessIoc",
        "isolatedMountDrift",
        "ksuThroneHunt",
        "ksuManagerFingerprint",
        "runtimeArtifacts",
        "cgroupLeakage",
        "kernelTraces",
        "propertyResidue",
        "tempRootArtifacts",
        "nativeLibrary",
        "signalSummary",
    ).map { label ->
        NativeRootDetailRowModel(
            label = label,
            value = value,
            status = status,
        )
    }
}

private fun methodStatus(result: NativeRootMethodResult): DetectorStatus {
    return when (result.outcome) {
        NativeRootMethodOutcome.CLEAN -> DetectorStatus.allClear()
        NativeRootMethodOutcome.DETECTED -> DetectorStatus.danger()
        NativeRootMethodOutcome.WARNING -> DetectorStatus.warning()
        NativeRootMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
    }
}

internal fun buildThroneHuntDiagnostics(report: NativeRootReport): String {
    // The copy payload prefers the primary summary over string placeholders because the same
    // text must remain useful when the visible row is later redesigned.
    // 复制载荷优先使用主 evidence 字段而不是占位字符串；即使可见行以后重新设计，
    // 这份文本仍然有用。
    return buildString {
        appendLine("NativeRoot ksuThroneHunt diagnostic")
        appendLine("available=${report.ksuThroneHuntAvailable}")
        appendLine("collectionOutcome=${report.ksuThroneHuntCollectionOutcome}")
        appendLine("collectionDetail=${report.ksuThroneHuntCollectionDetail}")
        appendLine("failureStage=${report.ksuThroneHuntFailureStage}")
        appendLine("stimulusApplied=${report.ksuThroneHuntStimulusApplied}")
        appendLine("stimulus=${report.ksuThroneHuntStimulusDetail}")
        appendLine("packageDirectory=${report.ksuThroneHuntPackageDirectory}")
        appendLine("watchDescriptor=${report.ksuThroneHuntWatchDescriptor}")
        appendLine("watchDenied=${report.ksuThroneHuntWatchDenied}")
        appendLine("open=${report.ksuThroneHuntOpenCount}")
        appendLine("access=${report.ksuThroneHuntAccessCount}")
        appendLine("raw=${report.ksuThroneHuntRawEventCount}")
        appendLine("invalid=${report.ksuThroneHuntInvalidEventCount}")
        appendLine("baseline=${report.ksuThroneHuntBaselineHitCount}")
        if (report.ksuThroneHuntDiagnosticDetail.isNotBlank()) {
            appendLine("--- detail ---")
            append(report.ksuThroneHuntDiagnosticDetail)
        }
    }
}
