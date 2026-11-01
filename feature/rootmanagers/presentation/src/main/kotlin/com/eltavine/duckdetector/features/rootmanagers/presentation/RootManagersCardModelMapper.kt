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
import com.eltavine.duckdetector.features.rootmanagers.domain.ProfileScanState
import com.eltavine.duckdetector.features.rootmanagers.domain.RootManagerConfidence
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.rootmanagers.domain.RootManagersOutcome
import com.eltavine.duckdetector.features.rootmanagers.domain.RootManagersReport
import com.eltavine.duckdetector.features.rootmanagers.domain.outcome
import com.eltavine.duckdetector.features.rootmanagers.domain.toDetectorStatus
import com.eltavine.duckdetector.features.rootmanagers.presentation.model.RootManagersCardModel

class RootManagersCardModelMapper {

    private val rows = RootManagersRows()

    fun map(report: RootManagersReport): RootManagersCardModel {
        val outcome = report.outcome()
        return RootManagersCardModel(
            title = TITLE,
            subtitle = subtitle(report),
            status = report.toDetectorStatus(),
            verdict = verdict(outcome),
            summary = summary(report, outcome),
            entryRows = report.entries.map(rows::entryRow),
            profileRows = report.profileScans.map { scan ->
                val matched = report.entries.filter { it.profileUserId == scan.profileUserId }
                val row = rows.profileRow(scan)
                if (scan.state != ProfileScanState.SEARCHED || matched.isEmpty()) row else row.copy(
                    value = "${row.value} · ${matched.size} match(es)",
                    status = when {
                        matched.any { it.concealed } -> DetectorStatus.danger()
                        matched.any { it.confidence != RootManagerConfidence.LOW } -> DetectorStatus.warning()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                )
            },
            scanRows = rows.scanRows(report),
            headerFacts = rootManagersHeaderFacts(report),
            impactRows = rootManagersImpactRows(report),
            methodRows = rootManagersMethodRows(report),
        )
    }

    private fun subtitle(report: RootManagersReport): String = when (report.outcome()) {
        RootManagersOutcome.SCANNING, RootManagersOutcome.FAILED -> SUBTITLE
        else -> "${report.entries.size} matched · ${report.appsChecked} apps checked · " +
            "${report.profilesSearched} profile(s) searched"
    }

    private fun verdict(outcome: RootManagersOutcome): String = when (outcome) {
        RootManagersOutcome.SCANNING -> "Scanning"
        RootManagersOutcome.FAILED -> "Scan failed"
        RootManagersOutcome.CONCEALED_MANAGER -> "Root manager hiding its icon"
        RootManagersOutcome.MANAGER_FOUND -> "Root manager apps found"
        RootManagersOutcome.WEAK_MATCH -> "Weak root manager match"
        RootManagersOutcome.PERMISSION_ANCHOR -> "Candidate permission owner observed"
        RootManagersOutcome.ENUMERATION_UNAVAILABLE -> "Launcher enumeration unavailable"
        RootManagersOutcome.PROFILES_NOT_ENUMERATED -> "Profiles not enumerated"
        RootManagersOutcome.PARTIAL -> "Partially evaluated"
        RootManagersOutcome.CLEAN -> "No root manager apps"
    }

    private fun summary(report: RootManagersReport, outcome: RootManagersOutcome): String = when (outcome) {
        RootManagersOutcome.SCANNING ->
            "Checking installed apps across the accessible profiles."

        RootManagersOutcome.FAILED ->
            report.issues.firstOrNull() ?: "The scan failed before the enumeration ran."

        RootManagersOutcome.CONCEALED_MANAGER ->
            "Identified ${report.entries.size} root manager app(s); at least one disabled its launcher " +
                "icon and is reachable only through app details. $PRESENCE_NOT_ROOT"

        RootManagersOutcome.MANAGER_FOUND ->
            "Identified ${report.entries.size} root manager app(s) across ${report.profilesSearched} profile(s), " +
                "${report.entries.count { it.matchedCertificate != null }} by a family kernel's manager key. " +
                PRESENCE_NOT_ROOT

        RootManagersOutcome.PERMISSION_ANCHOR ->
            "${report.installerCanary.ownerPackageName} declares the candidate KernelSU permission. " +
                "This is a permission-name anchor; manager identity, profile and root access are not established by it."

        RootManagersOutcome.WEAK_MATCH ->
            "Only weak anchors matched, so these apps are informational, never warnings."

        RootManagersOutcome.ENUMERATION_UNAVAILABLE ->
            report.issues.firstOrNull()
                ?: "The launcher enumeration was unavailable, so the absence of matches says nothing."

        RootManagersOutcome.PROFILES_NOT_ENUMERATED ->
            "No profile could be enumerated, so the absence of matches says nothing."

        RootManagersOutcome.PARTIAL ->
            "No root manager matched, but ${gaps(report).joinToString(", ")}, so the absence of matches is not proof."

        RootManagersOutcome.CLEAN ->
            "Checked ${report.appsChecked} app(s) across ${report.profilesSearched} profile(s), including " +
                "${report.coverage.certificatesRead} signing certificates, and matched no root manager app."
    }

    private fun gaps(report: RootManagersReport): List<String> = buildList {
        if (report.profileScans.any { it.state != ProfileScanState.SEARCHED }) add("a profile was not observed")
        if (report.coverage.callerSelfObserved == false) add("this app was missing from its own launcher list")
        if (report.coverage.packageVisibility != InstalledPackageVisibility.FULL) add("package visibility is not full")
        if (report.coverage.certificatesUnavailable) add("no signing certificate could be read")
    }.ifEmpty { listOf("part of the evidence could not be read") }

    private companion object {
        const val TITLE = "Root Managers"
        const val SUBTITLE = "Root manager visibility"
        const val PRESENCE_NOT_ROOT = "A match is evidence an app is installed, not proof that the device is rooted."
    }
}
