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

package com.eltavine.duckdetector.features.dangerousapps.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsReport
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsStage
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousDetectionMethodKind
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckKind
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckState
import com.eltavine.duckdetector.features.dangerousapps.domain.ThanoxIpcState
import com.eltavine.duckdetector.features.dangerousapps.domain.toDetectorStatus
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsDetailRowModel
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsHeaderFact
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsHeaderFactModel

internal fun dangerousAppsImpactRows(report: DangerousAppsReport): List<DangerousAppsDetailRowModel> = listOf(
    DangerousAppsDetailRowModel("Interpretation", when {
        report.stage != DangerousAppsStage.READY -> "Evaluation incomplete"
        report.hiddenCount > 0 -> "Package visibility mismatch"
        report.behaviorChecks.any { it.state in setOf(HmaCheckState.INCONSISTENT, HmaCheckState.TIMING_ANOMALY) } -> "Behavior evidence observed"
        report.detectedCount > 0 -> "Catalog package presence"
        report.thanoxIpc.state == ThanoxIpcState.MATCHED -> "Runtime service presence"
        else -> "Available evidence only"
    }, report.toDetectorStatus(),
        "Package matches, runtime interfaces and platform behavior checks have separate scopes. Behavior mismatches do not identify a hiding module; timing anomalies have lower confidence. Package history does not establish current installation, and none of these observations proves root access."),
)

internal fun dangerousAppsMethodRows(report: DangerousAppsReport): List<DangerousAppsDetailRowModel> {
    if (report.stage != DangerousAppsStage.READY) {
        return listOf(DangerousAppsDetailRowModel("Package and behavior probes",
            if (report.stage == DangerousAppsStage.LOADING) "Pending" else "Unavailable", report.toDetectorStatus()))
    }
    return report.probesRan.filter { it != DangerousDetectionMethodKind.THANOX_IPC }.map { method ->
        val hits = report.findings.count { finding -> finding.methods.any { it.kind == method } }
        val hidden = report.hiddenFromPackageManager.any { finding -> finding.methods.any { it.kind == method && it.hmaEligible } }
        DangerousAppsDetailRowModel(method.label, "$hits package hit(s)", when {
            hidden -> DetectorStatus.danger()
            hits > 0 -> DetectorStatus.warning()
            else -> DetectorStatus.info(InfoKind.SUPPORT)
        }, "A listed probe ran in this scan. Zero hits do not establish full visibility; related package probes can share the same underlying mechanism.")
    } + report.thanoxIpc.toMethodRow() + report.behaviorChecks.map { check ->
        DangerousAppsDetailRowModel(check.kind.label, check.state.label, when (check.state) {
            HmaCheckState.INCONSISTENT, HmaCheckState.TIMING_ANOMALY -> DetectorStatus.warning()
            HmaCheckState.CONSISTENT -> DetectorStatus.allClear()
            HmaCheckState.UNAVAILABLE -> DetectorStatus.info(InfoKind.ERROR)
            HmaCheckState.EXPERIMENTAL_ANOMALY, HmaCheckState.UNSUPPORTED, HmaCheckState.INCONCLUSIVE,
            HmaCheckState.PERMISSION_LIMITED, HmaCheckState.PARTIAL -> DetectorStatus.info(InfoKind.SUPPORT)
        }, buildString {
            append(check.detail)
            if (check.packages.isNotEmpty()) append(" Packages: ${check.packages.joinToString()}.")
            if (check.uids.isNotEmpty()) append(" UIDs: ${check.uids.joinToString()}.")
        })
    }
}

internal fun dangerousAppsRuntimeFact(report: DangerousAppsReport): DangerousAppsHeaderFactModel {
    val hits = report.behaviorChecks.count { it.state in setOf(HmaCheckState.INCONSISTENT, HmaCheckState.TIMING_ANOMALY) } +
        if (report.thanoxIpc.state == ThanoxIpcState.MATCHED) 1 else 0
    val behaviorKinds = report.behaviorChecks.mapTo(mutableSetOf()) { it.kind }
    val complete = report.thanoxIpc.complete && behaviorKinds.containsAll(HmaCheckKind.entries) &&
        report.behaviorChecks.all { it.state == HmaCheckState.CONSISTENT }
    val value = when {
        hits > 0 || complete -> "$hits signal(s)"
        report.behaviorChecks.any { it.state == HmaCheckState.EXPERIMENTAL_ANOMALY } -> "Experimental observation"
        else -> "Incomplete"
    }
    return DangerousAppsHeaderFactModel(DangerousAppsHeaderFact.RUNTIME,
        value, when {
            hits > 0 -> DetectorStatus.warning()
            complete -> DetectorStatus.allClear()
            else -> DetectorStatus.info(InfoKind.SUPPORT)
        })
}
