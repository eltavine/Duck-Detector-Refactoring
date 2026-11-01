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

package com.eltavine.duckdetector.features.rootmanagers.presentation

import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.rootmanagers.domain.ProfileScanState
import com.eltavine.duckdetector.features.rootmanagers.domain.RootManagerConfidence
import com.eltavine.duckdetector.features.rootmanagers.domain.RootManagerEntry
import com.eltavine.duckdetector.features.rootmanagers.domain.RootManagersEnumerationState
import com.eltavine.duckdetector.features.rootmanagers.domain.RootManagersProfileScan
import com.eltavine.duckdetector.features.rootmanagers.domain.RootManagersReport
import com.eltavine.duckdetector.features.rootmanagers.domain.RootManagersStage
import com.eltavine.duckdetector.features.rootmanagers.domain.toDetectorStatus
import com.eltavine.duckdetector.features.rootmanagers.presentation.model.RootManagersDetailRowModel

/**
 * Builds the card's rows. Every hidden copy carries the matched apps and the scan's counts only:
 * the unmatched apps are the user's inventory, so they never reach a row, a copy or the export.
 */
internal class RootManagersRows {

    fun entryRow(entry: RootManagerEntry): RootManagersDetailRowModel {
        val detail = buildString {
            append("@user ${entry.profileUserId} · anchors: ${entry.anchorList()}")
            if (entry.matchedCertificate != null) append(" · signed with the ${entry.family.displayName} manager key")
            if (entry.matchedPayloads.isNotEmpty()) append(" · payload: ${entry.matchedPayloads.joinToString(", ")}")
            if (entry.hidesLauncherIcon) append(" · launcher icon hidden")
        }
        return RootManagersDetailRowModel(
            label = "${entry.displayName} (${entry.packageName})",
            value = entry.confidence.displayName,
            status = entryStatus(entry),
            detail = detail,
            hiddenCopyText = entryDiagnostics(entry),
        )
    }

    fun profileRow(scan: RootManagersProfileScan): RootManagersDetailRowModel {
        val value = when (scan.state) {
            ProfileScanState.SEARCHED -> "${scan.appsChecked} apps checked"
            ProfileScanState.EMPTY -> "Not observed"
            ProfileScanState.DENIED -> "Denied"
        }
        val status = when (scan.state) {
            ProfileScanState.SEARCHED -> DetectorStatus.allClear()
            ProfileScanState.EMPTY -> DetectorStatus.info(InfoKind.SUPPORT)
            ProfileScanState.DENIED -> DetectorStatus.info(InfoKind.ERROR)
        }
        return RootManagersDetailRowModel(
            label = "user ${scan.profileUserId}",
            value = value,
            status = status,
            hiddenCopyText = buildString {
                appendLine("Root Managers profile scan")
                appendLine("Profile user id: ${scan.profileUserId}")
                appendLine("State: ${scan.state}")
                appendLine("Launcher activities seen: ${scan.launcherActivitiesSeen}")
                append("Apps checked: ${scan.appsChecked}")
            },
        )
    }

    fun scanRows(report: RootManagersReport): List<RootManagersDetailRowModel> {
        if (report.stage != RootManagersStage.READY) {
            return emptyList()
        }
        val diagnostics = enumerationDiagnostics(report)
        val coverage = report.coverage
        fun row(label: String, value: String, status: DetectorStatus, detail: String? = null) =
            RootManagersDetailRowModel(label, value, status, detail, detail != null, diagnostics)

        return buildList {
            addAll(installerCanaryRows(report.installerCanary))
            add(row("Enumeration", enumerationLabel(report.enumerationState), enumerationStatus(report.enumerationState)))
            add(
                row(
                    label = "Profiles searched",
                    value = "${report.profilesSearched} of ${report.profileScans.size}",
                    status = if (report.profileScans.all { it.state == ProfileScanState.SEARCHED }) {
                        DetectorStatus.allClear()
                    } else {
                        DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
            )
            add(row("Apps checked", report.appsChecked.toString(), DetectorStatus.allClear()))
            add(
                row(
                    label = "Signing certificates",
                    value = "${coverage.certificatesRead} read · ${coverage.certificateReadFailures} failed",
                    status = when {
                        coverage.certificatesUnavailable -> DetectorStatus.info(InfoKind.ERROR)
                        coverage.certificateReadFailures > 0 -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.allClear()
                    },
                ),
            )
            add(
                row(
                    label = "Native payload directories",
                    value = "${coverage.payloadDirectoriesRead} read · ${coverage.payloadDirectoryFailures} failed",
                    status = if (coverage.payloadDirectoryFailures > 0) {
                        DetectorStatus.info(InfoKind.SUPPORT)
                    } else {
                        DetectorStatus.allClear()
                    },
                ),
            )
            add(row("Package visibility", visibilityLabel(coverage.packageVisibility), visibilityStatus(coverage.packageVisibility)))
            add(row("Launcher self-check", selfCheckLabel(coverage.callerSelfObserved), selfCheckStatus(coverage.callerSelfObserved)))
            add(row("Matched apps", report.entries.size.toString(), report.toDetectorStatus()))
            if (report.issues.isNotEmpty()) {
                add(
                    row(
                        label = "Issues",
                        value = report.issues.size.toString(),
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                        detail = report.issues.joinToString(separator = "\n"),
                    ),
                )
            }
        }
    }

    private fun entryStatus(entry: RootManagerEntry): DetectorStatus = when {
        entry.concealed -> DetectorStatus.danger()
        entry.confidence == RootManagerConfidence.LOW -> DetectorStatus.info(InfoKind.SUPPORT)
        else -> DetectorStatus.warning()
    }

    private fun enumerationLabel(state: RootManagersEnumerationState): String = when (state) {
        RootManagersEnumerationState.EVALUATED -> "Searched"
        RootManagersEnumerationState.UNAVAILABLE -> "Unavailable"
        RootManagersEnumerationState.UNDECIDABLE -> "No profiles"
    }

    private fun enumerationStatus(state: RootManagersEnumerationState): DetectorStatus = when (state) {
        RootManagersEnumerationState.EVALUATED -> DetectorStatus.allClear()
        RootManagersEnumerationState.UNAVAILABLE -> DetectorStatus.info(InfoKind.ERROR)
        RootManagersEnumerationState.UNDECIDABLE -> DetectorStatus.info(InfoKind.SUPPORT)
    }

    private fun visibilityLabel(visibility: InstalledPackageVisibility): String = when (visibility) {
        InstalledPackageVisibility.FULL -> "Full"
        InstalledPackageVisibility.RESTRICTED -> "Filtered"
        InstalledPackageVisibility.UNKNOWN -> "Unknown"
    }

    private fun visibilityStatus(visibility: InstalledPackageVisibility): DetectorStatus = when (visibility) {
        InstalledPackageVisibility.FULL -> DetectorStatus.allClear()
        InstalledPackageVisibility.RESTRICTED -> DetectorStatus.info(InfoKind.SUPPORT)
        InstalledPackageVisibility.UNKNOWN -> DetectorStatus.info(InfoKind.ERROR)
    }

    private fun selfCheckLabel(observed: Boolean?): String = when (observed) {
        true -> "Observed"
        false -> "Missing"
        null -> "Not applicable"
    }

    private fun selfCheckStatus(observed: Boolean?): DetectorStatus = when (observed) {
        true -> DetectorStatus.allClear()
        false -> DetectorStatus.info(InfoKind.ERROR)
        null -> DetectorStatus.info(InfoKind.SUPPORT)
    }

    private fun RootManagerEntry.anchorList(): String =
        anchors.sortedBy { anchor -> anchor.ordinal }.joinToString(", ") { anchor -> anchor.displayName }

    private fun entryDiagnostics(entry: RootManagerEntry): String = buildString {
        appendLine("Root manager match")
        appendLine("Family: ${entry.family.displayName}")
        appendLine("Package: ${entry.packageName}")
        appendLine("Label: ${entry.displayName}")
        appendLine("Profile user id: ${entry.profileUserId}")
        appendLine("Confidence: ${entry.confidence.displayName}")
        appendLine("Anchors: ${entry.anchorList()}")
        appendLine("Signing key: ${entry.matchedCertificate?.let { "${it.sizeBytes} bytes, sha256 ${it.sha256}" } ?: "no catalogued key"}")
        appendLine("Native payloads: ${entry.matchedPayloads.joinToString(", ").ifEmpty { "none" }}")
        appendLine("Launcher icon hidden: ${entry.hidesLauncherIcon}")
        appendLine("Component class: ${entry.componentClassName ?: "none"}")
        appendLine("Application class: ${entry.applicationClassName ?: "none"}")
        appendLine("Source dir: ${entry.sourceDir ?: "none"}")
        appendLine("UID: ${entry.uid?.toString() ?: "unknown"}")
        append("First install time: ${entry.firstInstallTime?.toString() ?: "unknown"}")
    }

    private fun enumerationDiagnostics(report: RootManagersReport): String = buildString {
        val coverage = report.coverage
        appendLine("Root Managers enumeration")
        appendLine("Stage: ${report.stage}")
        appendLine("Enumeration state: ${report.enumerationState}")
        appendLine("Complete: ${report.complete}")
        appendLine("Profiles searched: ${report.profilesSearched} of ${report.profileScans.size}")
        appendLine("Launcher activities seen: ${report.launcherActivitiesSeen}")
        appendLine("Apps checked: ${report.appsChecked}")
        appendLine("Signing certificates: ${coverage.certificatesRead} read, ${coverage.certificateReadFailures} failed")
        appendLine("Native payload directories: ${coverage.payloadDirectoriesRead} read, ${coverage.payloadDirectoryFailures} failed")
        appendLine("Package visibility: ${coverage.packageVisibility}")
        appendLine("Launcher self-check: ${coverage.callerSelfObserved ?: "not applicable"}")
        appendLine("Matched apps: ${report.entries.size}")
        report.profileScans.forEach { scan ->
            appendLine("  user ${scan.profileUserId}: ${scan.state}, launcher=${scan.launcherActivitiesSeen}, apps=${scan.appsChecked}")
        }
        if (report.issues.isNotEmpty()) {
            appendLine("Issues:")
            report.issues.forEach { issue -> appendLine("  $issue") }
        }
    }
}
