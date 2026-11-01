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

package com.eltavine.duckdetector.features.mount.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.mount.domain.MountReport
import com.eltavine.duckdetector.features.mount.domain.MountRootToken
import com.eltavine.duckdetector.features.mount.domain.MountStage
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextNamespaceAssessment
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextReport
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextState
import com.eltavine.duckdetector.features.mount.presentation.model.MountDetailRowModel

internal fun procMountViewRow(report: MountReport): MountDetailRowModel {
    // Keep the row visible even when another probe fails; detail stays in hiddenCopyText.
    // 其他 probe 失败时仍保留该 row，完整 detail 通过 hiddenCopyText 取证复制。
    val value = when {
        report.stage == MountStage.LOADING -> "Pending"
        report.procMountViewRootToken == MountRootToken.KSU -> "KSU mount"
        report.procMountViewRootToken == MountRootToken.MAGISK -> "Magisk mount"
        report.procMountViewTokenHit -> "Root mount"
        report.procMountViewDivergent -> "${report.procMountViewDistinctCount} view(s)"
        report.procMountViewProbeAvailable -> "Clean"
        else -> "Unavailable"
    }
    val status = when {
        report.stage == MountStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
        report.procMountViewTokenHit -> DetectorStatus.danger()
        report.procMountViewDivergent -> DetectorStatus.warning()
        report.procMountViewProbeAvailable -> DetectorStatus.allClear()
        else -> DetectorStatus.info(InfoKind.SUPPORT)
    }
    val detail = report.procMountViewDetail.ifBlank {
        "The isolated helper process did not return cross-process mount view data."
    }
    val visibleDetail = when {
        report.procMountViewTokenDetail.isNotBlank() -> report.procMountViewTokenDetail
        report.procMountViewDivergent -> detail
        else -> null
    }
    return MountDetailRowModel(
        label = "Cross-process mount views",
        value = value,
        status = status,
        detail = visibleDetail,
        detailMonospace = visibleDetail != null,
        hiddenCopyText = buildString {
            appendLine("Cross-process mount views")
            appendLine("Result: $value")
            appendLine("Probe available: ${report.procMountViewProbeAvailable}")
            appendLine("Distinct views: ${report.procMountViewDistinctCount}")
            appendLine("Expected views: ${report.procMountViewExpectedCount}")
            appendLine("Scanned PIDs: ${report.procMountViewPidCount}")
            appendLine("Divergent: ${report.procMountViewDivergent}")
            appendLine("Root token hit: ${report.procMountViewTokenHit}")
            appendLine(
                "Matched token: ${report.procMountViewRootToken?.sequence ?: "None"}",
            )
            appendLine(
                "Matched mountinfo line: ${report.procMountViewTokenDetail.ifBlank { "None" }}",
            )
            append("Detail: $detail")
        },
    )
}

internal fun zygoteNextMountViewRow(report: MountReport): MountDetailRowModel {
    val result = report.zygoteNext
    val value = when (result.state) {
        MountZygoteNextState.PENDING -> "Pending"
        MountZygoteNextState.UNSUPPORTED -> "Requires Android 17"
        MountZygoteNextState.UNAVAILABLE -> "Unavailable"
        MountZygoteNextState.READY -> if (result.leakDetected) {
            "Root mount"
        } else {
            when (result.namespaceAssessment) {
                MountZygoteNextNamespaceAssessment.PRIVATE_ANOMALY -> "Namespace observation"
                MountZygoteNextNamespaceAssessment.INCONSISTENT -> "Namespace observation"
                MountZygoteNextNamespaceAssessment.UNVERIFIED -> "Coverage unverified"
                MountZygoteNextNamespaceAssessment.LIKELY_INIT -> "Clean"
            }
        }
    }
    val status = when (result.state) {
        MountZygoteNextState.PENDING,
        MountZygoteNextState.UNSUPPORTED,
        MountZygoteNextState.UNAVAILABLE -> DetectorStatus.info(InfoKind.SUPPORT)

        MountZygoteNextState.READY -> if (result.leakDetected) {
            DetectorStatus.danger()
        } else {
            when (result.namespaceAssessment) {
                MountZygoteNextNamespaceAssessment.PRIVATE_ANOMALY,
                MountZygoteNextNamespaceAssessment.INCONSISTENT -> DetectorStatus.info(InfoKind.SUPPORT)

                MountZygoteNextNamespaceAssessment.UNVERIFIED ->
                    DetectorStatus.info(InfoKind.SUPPORT)

                MountZygoteNextNamespaceAssessment.LIKELY_INIT -> DetectorStatus.allClear()
            }
        }
    }
    val markerDetail = result.dangerousMarkers.joinToString("\n") { marker ->
        "${marker.labels.joinToString("+")}: ${marker.rawLine}"
    }
    val detail = when {
        markerDetail.isNotBlank() -> markerDetail
        result.state == MountZygoteNextState.UNAVAILABLE -> result.errorDetail
        result.state == MountZygoteNextState.READY && !result.hasInitNamespaceCoverage ->
            result.namespaceAssessmentDetail

        else -> null
    }
    return MountDetailRowModel(
        label = "Zygote next mount view",
        value = value,
        status = status,
        detail = detail,
        detailMonospace = markerDetail.isNotBlank(),
        hiddenCopyText = buildZygoteNextCopyText(result, value),
    )
}

private fun buildZygoteNextCopyText(
    result: MountZygoteNextReport,
    value: String,
): String {
    return buildString {
        appendLine("Zygote next mount view")
        appendLine("Result: $value")
        appendLine("State: ${result.state}")
        appendLine("SDK: ${result.sdkInt}")
        appendLine("Main namespace: ${namespaceLabel(result.mainNamespaceInode)}")
        appendLine("Main propagation: ${result.mainPropagation.ifBlank { "Unclassified" }}")
        appendLine(
            "Main mount IDs: root=${mountIdLabel(result.mainRootMountId)}, " +
                "range=${mountIdRange(result.mainMinimumMountId, result.mainMaximumMountId)}",
        )
        appendLine("Main mount entries: ${result.mainMountCount}")
        appendLine("Isolated namespace: ${namespaceLabel(result.isolatedNamespaceInode)}")
        appendLine(
            "Isolated propagation: ${result.isolatedPropagation.ifBlank { "Unclassified" }}",
        )
        appendLine(
            "Isolated mount IDs: root=${mountIdLabel(result.isolatedRootMountId)}, " +
                "range=${mountIdRange(result.isolatedMinimumMountId, result.isolatedMaximumMountId)}",
        )
        appendLine("Isolated mount entries: ${result.isolatedMountCount}")
        appendLine("Namespace assessment: ${result.namespaceAssessment}")
        appendLine("Init-managed namespace coverage: ${result.hasInitNamespaceCoverage}")
        appendLine("Shared-view contrast: ${result.contrastObserved}")
        appendLine("Root marker leak: ${result.leakDetected}")
        appendLine("Main markers:")
        appendMarkers(result.mainMarkers)
        appendLine("Isolated markers:")
        appendMarkers(result.isolatedMarkers)
        append("Detail: ${result.errorDetail.ifBlank { "None" }}")
    }
}

private fun mountIdLabel(value: Long): String {
    return value.takeIf { it > 0L }?.toString() ?: "Unreadable"
}

private fun mountIdRange(minimum: Long, maximum: Long): String {
    return if (minimum > 0L && maximum >= minimum) "$minimum..$maximum" else "Unreadable"
}

private fun StringBuilder.appendMarkers(
    markers: List<com.eltavine.duckdetector.features.mount.domain.MountZygoteNextMarker>,
) {
    if (markers.isEmpty()) {
        appendLine("None")
        return
    }
    markers.forEach { marker ->
        appendLine("${marker.labels.joinToString("+")}: ${marker.rawLine}")
    }
}

private fun namespaceLabel(inode: Long): String {
    return if (inode == 0L) "Unreadable" else "mnt:[$inode]"
}
