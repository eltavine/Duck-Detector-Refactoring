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

package com.eltavine.duckdetector.features.dangerousapps.presentation

import com.eltavine.duckdetector.core.ui.model.ContextItemModel
import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppFinding
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsReport
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsStage
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility
import com.eltavine.duckdetector.features.dangerousapps.ui.model.DangerousAppsCardModel
import com.eltavine.duckdetector.features.dangerousapps.ui.model.DangerousAppsHeaderFactModel
import com.eltavine.duckdetector.features.dangerousapps.ui.model.DangerousAppsHiddenPackageItemModel
import com.eltavine.duckdetector.features.dangerousapps.ui.model.DangerousAppsHmaAlertModel
import com.eltavine.duckdetector.features.dangerousapps.ui.model.DangerousAppsPackageItemModel
import com.eltavine.duckdetector.features.dangerousapps.ui.model.DangerousAppsTargetAppModel

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
                report.detectedCount > 0 -> "${report.detectedCount} risky package(s) surfaced"
                report.suspiciousLowPmInventory -> "Package inventory unusually small"
                report.packageVisibility == DangerousPackageVisibility.RESTRICTED -> "Inventory visibility limited"
                else -> "No known risky packages"
            }
        }
    }

    private fun buildSummary(report: DangerousAppsReport): String {
        return when (report.stage) {
            DangerousAppsStage.LOADING ->
                "PackageManager, open APK descriptors, storage mirrors, loopback, IPC, accessibility, and native package-path probes are collecting local evidence."

            DangerousAppsStage.FAILED ->
                report.issues.firstOrNull()
                    ?: "Dangerous app scan failed before inventory could be built."

            DangerousAppsStage.READY -> when {
                report.hiddenCount > 0 ->
                    "${report.hiddenCount} package(s) were visible to non-PackageManager probes but absent from PackageManager."

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

                report.suspiciousLowPmInventory ->
                    "PackageManager reported a full inventory surface but returned only ${report.packageManagerVisibleCount} visible packages. That is unusually low for a modern device and can happen under HMA-style whitelist filtering."

                report.packageVisibility == DangerousPackageVisibility.RESTRICTED ->
                    "Open APK descriptor and storage-side probes still ran, but a clean result may under-report installed tools when PackageManager visibility is scoped."

                else ->
                    "PackageManager, open APK descriptors, storage, loopback, IPC, accessibility, and native package-path probes did not surface known high-risk tools."
            }
        }
    }

    private fun buildHeaderFacts(report: DangerousAppsReport): List<DangerousAppsHeaderFactModel> {
        return listOf(
            DangerousAppsHeaderFactModel(
                label = "Targets",
                value = report.targets.size.toString(),
                status = DetectorStatus.allClear(),
            ),
            DangerousAppsHeaderFactModel(
                label = "PM",
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
                label = "Hits",
                value = report.detectedCount.toString(),
                status = if (report.detectedCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
            ),
            DangerousAppsHeaderFactModel(
                label = "Hidden",
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
            summary = "These packages were detected by non-PackageManager probes but hidden from PackageManager. This is the only Dangerous Apps path that stays red.",
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

    private fun buildContext(report: DangerousAppsReport): List<ContextItemModel> {
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
            ContextItemModel("Inventory", "${report.targets.size} legacy packages"),
            ContextItemModel("PackageManager", visibilityLongLabel(report.packageVisibility)),
            ContextItemModel(
                "Visible packages",
                if (report.packageManagerVisibleCount > 0) {
                    report.packageManagerVisibleCount.toString()
                } else {
                    "Unavailable"
                },
            ),
            ContextItemModel("Categories", categories),
            ContextItemModel("Probe families", probeSummary),
        )
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

    private fun DangerousAppsReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            DangerousAppsStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            DangerousAppsStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            DangerousAppsStage.READY -> when {
                hiddenCount > 0 -> DetectorStatus.danger()
                detectedCount > 0 -> DetectorStatus.warning()
                suspiciousLowPmInventory -> DetectorStatus.warning()
                packageVisibility == DangerousPackageVisibility.RESTRICTED -> DetectorStatus.info(
                    InfoKind.ERROR
                )

                else -> DetectorStatus.allClear()
            }
        }
    }
}
