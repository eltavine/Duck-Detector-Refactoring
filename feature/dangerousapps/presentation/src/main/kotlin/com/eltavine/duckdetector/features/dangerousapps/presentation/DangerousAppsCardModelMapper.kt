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
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppFinding
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsReport
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsStage
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckState
import com.eltavine.duckdetector.features.dangerousapps.domain.toDetectorStatus
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsCardModel
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsContextItemModel
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsHeaderFact
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsHeaderFactModel
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsHiddenPackageItemModel
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsHmaAlertModel
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsPackageItemModel
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsTargetAppModel

class DangerousAppsCardModelMapper {

    fun map(
        report: DangerousAppsReport,
    ): DangerousAppsCardModel {
        return DangerousAppsCardModel(
            title = "Dangerous Apps",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            hmaAlert = buildHmaAlert(report),
            packageItems = buildPackageItems(report),
            context = buildContext(report),
            targetApps = report.targets.map { target ->
                DangerousAppsTargetAppModel(
                    appName = target.appName,
                    packageName = target.packageName,
                    category = target.category.displayName,
                )
            },
        )
    }

    private fun buildSubtitle(report: DangerousAppsReport): String {
        val base = "${report.targets.size} legacy targets"
        return when (report.packageVisibility) {
            DangerousPackageVisibility.FULL -> if (report.packageManagerVisibleCount > 0) {
                "$base · full PM inventory · ${report.packageManagerVisibleCount} visible"
            } else {
                "$base · full PM inventory"
            }

            DangerousPackageVisibility.RESTRICTED -> if (report.packageManagerVisibleCount > 0) {
                "$base · scoped PM inventory · ${report.packageManagerVisibleCount} visible"
            } else {
                "$base · scoped PM inventory"
            }

            DangerousPackageVisibility.UNKNOWN -> base
        }
    }

    private fun buildVerdict(report: DangerousAppsReport): String {
        return when (report.stage) {
            DangerousAppsStage.LOADING -> "Scanning app inventory"
            DangerousAppsStage.FAILED -> "Inventory scan failed"
            DangerousAppsStage.READY -> when {
                report.hiddenCount > 0 -> "HMA-style concealment detected"
                report.behaviorChecks.any { it.state == HmaCheckState.INCONSISTENT } -> "Platform behavior mismatch observed"
                report.behaviorChecks.any { it.state == HmaCheckState.TIMING_ANOMALY } -> "Repeated callback timeout asymmetry"
                report.detectedCount > 0 -> "${report.detectedCount} risky package(s) surfaced"
                report.suspiciousSharedStorageDenied -> "Shared storage baseline denied"
                report.suspiciousLowPmInventory -> "Package inventory unusually small"
                report.packageVisibility == DangerousPackageVisibility.RESTRICTED -> "Inventory visibility limited"
                report.packageVisibility == DangerousPackageVisibility.UNKNOWN -> "Package inventory unavailable"
                report.behaviorChecks.any { it.state != HmaCheckState.CONSISTENT } -> "Behavior checks incomplete"
                else -> "No known risky packages"
            }
        }
    }

    private fun buildSummary(report: DangerousAppsReport): String {
        return when (report.stage) {
            DangerousAppsStage.LOADING ->
                "PackageManager, createPackageContext + ZipFile, open APK descriptors, storage mirrors, loopback, IPC, accessibility, and native package-path probes are collecting local evidence."

            DangerousAppsStage.FAILED ->
                report.issues.firstOrNull()
                    ?: "Dangerous app scan failed before inventory could be built."

            DangerousAppsStage.READY -> when {
                report.hiddenCount > 0 ->
                    "${report.hiddenCount} package(s) were visible to direct corroboration probes but absent from PackageManager inventory."

                report.behaviorChecks.any { it.state == HmaCheckState.INCONSISTENT } ->
                    "Controlled interface checks observed inconsistent exception, broadcast callback, UID visibility or seccomp getpriority behavior. These signals do not identify a specific hiding module."

                report.behaviorChecks.any { it.state == HmaCheckState.TIMING_ANOMALY } ->
                    "Target callbacks repeatedly missed their deadlines while interleaved caller controls succeeded. This is lower-confidence timing evidence; scheduling and OEM behavior can also delay delivery."

                report.detectedCount > 0 ->
                    buildString {
                        append(
                            "Matched ${report.detectedCount} package(s) across ${
                                report.findings.map { it.target.category }.distinct().size
                            } category(ies). All package hits stay warning-level unless HMA concealment is present."
                        )
                        if (report.suspiciousLowPmInventory) {
                            append(' ')
                            append(
                                "PackageManager still exposed only ${report.packageManagerVisibleCount} visible packages, which is unusually low and can happen under HMA-style whitelist filtering."
                            )
                        }
                    }

                report.suspiciousSharedStorageDenied ->
                    "Multiple fixed shared-storage baseline paths returned EACCES/EPERM under stat(). This suggests shared user gid or related zygote storage groups may have been restricted."

                report.suspiciousLowPmInventory ->
                    "PackageManager reported a full inventory surface but returned only ${report.packageManagerVisibleCount} visible packages. That is unusually low for a modern device and can happen under HMA-style whitelist filtering."

                report.packageVisibility == DangerousPackageVisibility.RESTRICTED ->
                    "createPackageContext + ZipFile, open APK descriptor, and storage-side probes still ran, but a clean result may under-report installed tools when PackageManager visibility is scoped."

                report.packageVisibility == DangerousPackageVisibility.UNKNOWN ->
                    report.issues.firstOrNull()
                        ?: "PackageManager inventory was unavailable or anomalous, so package absence is inconclusive."

                report.behaviorChecks.any { it.state != HmaCheckState.CONSISTENT } ->
                    "No behavior mismatch was established, but some checks were partial, unavailable or inconclusive. Review each check's scope and controls."

                else ->
                    "PackageManager, createPackageContext + ZipFile, open APK descriptors, storage, loopback, IPC, accessibility, and native package-path probes did not surface known high-risk tools."
            }
        }
    }

    private fun buildHeaderFacts(report: DangerousAppsReport): List<DangerousAppsHeaderFactModel> {
        return listOf(
            DangerousAppsHeaderFactModel(
                fact = DangerousAppsHeaderFact.TARGETS,
                value = report.targets.size.toString(),
                status = DetectorStatus.allClear(),
            ),
            DangerousAppsHeaderFactModel(
                fact = DangerousAppsHeaderFact.PM,
                value = visibilityFactValue(report),
                status = when (report.packageVisibility) {
                    DangerousPackageVisibility.FULL -> if (report.suspiciousLowPmInventory) {
                        DetectorStatus.warning()
                    } else {
                        DetectorStatus.allClear()
                    }

                    DangerousPackageVisibility.RESTRICTED -> DetectorStatus.info(InfoKind.ERROR)
                    DangerousPackageVisibility.UNKNOWN -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            DangerousAppsHeaderFactModel(
                fact = DangerousAppsHeaderFact.HITS,
                value = report.detectedCount.toString(),
                status = if (report.detectedCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
            ),
            DangerousAppsHeaderFactModel(
                fact = DangerousAppsHeaderFact.HIDDEN,
                value = report.hiddenCount.toString(),
                status = if (report.hiddenCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
            ),
        )
    }

    private fun buildHmaAlert(report: DangerousAppsReport): DangerousAppsHmaAlertModel? {
        if (report.hiddenFromPackageManager.isEmpty()) {
            return null
        }
        return DangerousAppsHmaAlertModel(
            title = "HMA mismatch",
            summary = "These packages were detected by direct corroboration probes but hidden from PackageManager inventory. This is the only Dangerous Apps path that stays red.",
            hiddenPackages = report.hiddenFromPackageManager.map { finding ->
                DangerousAppsHiddenPackageItemModel(
                    appName = finding.target.appName,
                    packageName = finding.target.packageName,
                    methods = finding.methods.map { it.displayText },
                )
            },
        )
    }

    private fun buildPackageItems(report: DangerousAppsReport): List<DangerousAppsPackageItemModel> {
        return when (report.stage) {
            DangerousAppsStage.LOADING,
            DangerousAppsStage.FAILED -> emptyList()

            DangerousAppsStage.READY -> report.findings
                .sortedWith(
                    compareByDescending<DangerousAppFinding> { it.methods.size }
                        .thenBy { it.target.appName.lowercase() },
                )
                .map { finding ->
                    DangerousAppsPackageItemModel(
                        appName = finding.target.appName,
                        packageName = finding.target.packageName,
                        methods = finding.methods.map { it.displayText },
                    )
                }
        }
    }

    private fun buildContext(report: DangerousAppsReport): List<DangerousAppsContextItemModel> {
        val categories = report.findings
            .map { it.target.category.displayName }
            .distinct()
            .let { names ->
                when {
                    names.isEmpty() -> "None"
                    names.size <= 3 -> names.joinToString()
                    else -> names.take(3).joinToString() + " +${names.size - 3}"
                }
            }

        val probeSummary = when {
            report.probesRan.isEmpty() -> "Pending"
            report.probesRan.size <= 4 -> report.probesRan.joinToString { it.label }
            else -> report.probesRan.take(4)
                .joinToString { it.label } + " +${report.probesRan.size - 4}"
        }

        return listOf(
            DangerousAppsContextItemModel("Inventory", "${report.targets.size} legacy packages"),
            DangerousAppsContextItemModel("PackageManager", visibilityLongLabel(report.packageVisibility)),
            DangerousAppsContextItemModel(
                "Visible packages",
                if (report.packageManagerVisibleCount > 0) {
                    report.packageManagerVisibleCount.toString()
                } else {
                    "Unavailable"
                },
            ),
            DangerousAppsContextItemModel("Categories", categories),
            DangerousAppsContextItemModel("Probe families", probeSummary),
        ) + report.behaviorChecks.map { check ->
            DangerousAppsContextItemModel(check.kind.label, buildString {
                append("${check.state.label}. ${check.detail}")
                if (check.packages.isNotEmpty()) append(" Packages: ${check.packages.joinToString()}.")
                if (check.uids.isNotEmpty()) append(" UIDs: ${check.uids.joinToString()}.")
            })
        }
    }

    private fun visibilityFactValue(report: DangerousAppsReport): String {
        val base = visibilityLabel(report.packageVisibility)
        return if (report.packageManagerVisibleCount > 0) {
            "$base · ${report.packageManagerVisibleCount}"
        } else {
            base
        }
    }

    private fun visibilityLabel(visibility: DangerousPackageVisibility): String {
        return when (visibility) {
            DangerousPackageVisibility.FULL -> "Full"
            DangerousPackageVisibility.RESTRICTED -> "Scoped"
            DangerousPackageVisibility.UNKNOWN -> "Pending"
        }
    }

    private fun visibilityLongLabel(visibility: DangerousPackageVisibility): String {
        return when (visibility) {
            DangerousPackageVisibility.FULL -> "Full inventory access"
            DangerousPackageVisibility.RESTRICTED -> "Scoped inventory access"
            DangerousPackageVisibility.UNKNOWN -> "Not resolved yet"
        }
    }

}
