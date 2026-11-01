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

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.rootmanagers.domain.RootManagerConfidence
import com.eltavine.duckdetector.features.rootmanagers.domain.RootManagersEnumerationState
import com.eltavine.duckdetector.features.rootmanagers.domain.RootManagersReport
import com.eltavine.duckdetector.features.rootmanagers.domain.RootManagersStage
import com.eltavine.duckdetector.features.rootmanagers.domain.toDetectorStatus
import com.eltavine.duckdetector.features.rootmanagers.presentation.model.RootManagersDetailRowModel

internal fun rootManagersHeaderFacts(report: RootManagersReport): List<RootManagersDetailRowModel> {
    val ready = report.stage == RootManagersStage.READY
    if (!ready) {
        val value = if (report.stage == RootManagersStage.LOADING) "Pending" else "Unavailable"
        return listOf("Matches", "Concealed", "Apps checked", "Profiles").map {
            RootManagersDetailRowModel(it, value, report.toDetectorStatus())
        }
    }
    val support = DetectorStatus.info(InfoKind.SUPPORT)
    val matches = when {
        report.entries.isNotEmpty() -> report.toDetectorStatus()
        report.complete -> DetectorStatus.allClear()
        else -> support
    }
    return listOf(
        RootManagersDetailRowModel("Matches", report.entries.size.toString(), matches),
        RootManagersDetailRowModel("Concealed", report.entries.count { it.concealed }.toString(),
            if (report.entries.any { it.concealed }) DetectorStatus.danger() else if (report.complete) DetectorStatus.allClear() else support),
        RootManagersDetailRowModel("Apps checked", report.appsChecked.toString(), support),
        RootManagersDetailRowModel("Profiles", "${report.profilesSearched} of ${report.profileScans.size}", support),
    )
}

internal fun rootManagersImpactRows(report: RootManagersReport): List<RootManagersDetailRowModel> = listOf(
    RootManagersDetailRowModel("Evidence scope", when {
        report.entries.any { it.concealed } -> "Presence with concealed launcher"
        report.entries.any { it.confidence != RootManagerConfidence.LOW } -> "Manager app presence"
        report.entries.isNotEmpty() -> "Weak anchors only"
        report.complete -> "No catalog match observed"
        else -> "Coverage incomplete"
    }, report.toDetectorStatus(),
        "An app match does not establish root access, current execution or device compromise. Weak anchors and permission ownership alone do not identify a manager. Missing profiles or signing evidence limit absence conclusions."),
)

internal fun rootManagersMethodRows(report: RootManagersReport): List<RootManagersDetailRowModel> {
    if (report.stage != RootManagersStage.READY) {
        return listOf("Launcher enumeration", "Signing certificates", "Native payload directories", "Installer permission probe").map {
            RootManagersDetailRowModel(it, if (report.stage == RootManagersStage.LOADING) "Pending" else "Unavailable", report.toDetectorStatus())
        }
    }
    val coverage = report.coverage
    return listOf(
        RootManagersDetailRowModel(
            label = "Launcher enumeration",
            value = when (report.enumerationState) {
                RootManagersEnumerationState.EVALUATED -> "Searched"
                RootManagersEnumerationState.UNAVAILABLE -> "Unavailable"
                RootManagersEnumerationState.UNDECIDABLE -> "No profiles"
            },
            status = when (report.enumerationState) {
                RootManagersEnumerationState.EVALUATED -> DetectorStatus.allClear()
                RootManagersEnumerationState.UNAVAILABLE -> DetectorStatus.info(InfoKind.ERROR)
                RootManagersEnumerationState.UNDECIDABLE -> DetectorStatus.info(InfoKind.SUPPORT)
            },
            detail = "Accessible profiles and caller-profile package observations are matched against the manager catalog. Unmatched app identities are excluded from diagnostics.",
        ),
        RootManagersDetailRowModel(
            label = "Signing certificates",
            value = "${coverage.certificatesRead} read · ${coverage.certificateReadFailures} failed",
            status = when {
                report.entries.any { it.matchedCertificate != null } -> DetectorStatus.warning()
                coverage.certificatesUnavailable -> DetectorStatus.info(InfoKind.ERROR)
                coverage.certificateReadFailures > 0 || coverage.certificatesRead == 0 -> DetectorStatus.info(InfoKind.SUPPORT)
                else -> DetectorStatus.allClear()
            },
            detail = "Signing fingerprints provide catalog identity anchors; unreadable certificates reduce coverage.",
        ),
        RootManagersDetailRowModel(
            label = "Native payload directories",
            value = "${coverage.payloadDirectoriesRead} read · ${coverage.payloadDirectoryFailures} failed",
            status = when {
                report.entries.any { it.matchedPayloads.isNotEmpty() } -> DetectorStatus.warning()
                coverage.payloadDirectoryFailures > 0 || coverage.payloadDirectoriesRead == 0 -> DetectorStatus.info(InfoKind.SUPPORT)
                else -> DetectorStatus.allClear()
            },
            detail = "Visible payload names provide additional manager anchors; inaccessible directories remain unknown.",
        ),
    ) + installerCanaryRows(report.installerCanary).take(1)
}
