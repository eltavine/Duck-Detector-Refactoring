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

package com.eltavine.duckdetector.features.customrom.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.customrom.domain.CustomRomFinding
import com.eltavine.duckdetector.features.customrom.domain.CustomRomMethodOutcome
import com.eltavine.duckdetector.features.customrom.domain.CustomRomMethodResult
import com.eltavine.duckdetector.features.customrom.domain.CustomRomPackageVisibility
import com.eltavine.duckdetector.features.customrom.domain.CustomRomReport
import com.eltavine.duckdetector.features.customrom.domain.CustomRomStage
import com.eltavine.duckdetector.features.customrom.ui.model.CustomRomCardModel
import com.eltavine.duckdetector.features.customrom.ui.model.CustomRomDetailRowModel
import com.eltavine.duckdetector.features.customrom.ui.model.CustomRomHeaderFactModel
import com.eltavine.duckdetector.features.customrom.ui.model.CustomRomImpactItemModel

class CustomRomCardModelMapper {

    fun map(
        report: CustomRomReport,
    ): CustomRomCardModel {
        return CustomRomCardModel(
            title = "Custom ROM",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            buildRows = buildBuildRows(report),
            runtimeRows = buildRuntimeRows(report),
            frameworkRows = buildFrameworkRows(report),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }

    private fun buildSubtitle(report: CustomRomReport): String {
        return when (report.stage) {
            CustomRomStage.LOADING -> "properties + packages + services + native traces"
            CustomRomStage.FAILED -> "local aftermarket firmware probe failed"
            CustomRomStage.READY ->
                "${report.checkedPropertyCount} props · ${report.checkedPackageCount} packages · ${report.checkedServiceCount} named services"
        }
    }

    private fun buildVerdict(report: CustomRomReport): String {
        return when (report.stage) {
            CustomRomStage.LOADING -> "Scanning aftermarket firmware signals"
            CustomRomStage.FAILED -> "Custom ROM scan failed"
            CustomRomStage.READY -> when {
                report.detectedRoms.isEmpty() -> "No custom ROM signatures"
                report.detectedRoms.size == 1 -> "${report.detectedRoms.first()} signatures detected"
                else -> "${report.detectedRoms.size} ROM signatures detected"
            }
        }
    }

    private fun buildSummary(report: CustomRomReport): String {
        return when (report.stage) {
            CustomRomStage.LOADING ->
                "System properties, runtime packages/services, framework traces, and resource map checks are collecting local firmware evidence."

            CustomRomStage.FAILED ->
                report.errorMessage ?: "Custom ROM scan failed before evidence could be assembled."

            CustomRomStage.READY -> when {
                report.hasIndicators ->
                    "Build properties, runtime packages or services, framework traces, or resource map anomalies indicate aftermarket firmware or branded ROM components."

                report.nativeAvailable ->
                    "No common custom ROM branding, service, package, framework trace, or resource map anomaly surfaced from local probes."

                else ->
                    "Java-side probes were clean, but native framework trace coverage was unavailable on this build."
            }
        }
    }

    private fun buildHeaderFacts(report: CustomRomReport): List<CustomRomHeaderFactModel> {
        return when (report.stage) {
            CustomRomStage.LOADING -> placeholderFacts(
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            CustomRomStage.FAILED -> placeholderFacts("Error", DetectorStatus.info(InfoKind.ERROR))
            CustomRomStage.READY -> listOf(
                CustomRomHeaderFactModel(
                    label = "ROMs",
                    value = detectedRomValue(report),
                    status = if (report.detectedRoms.isEmpty()) DetectorStatus.allClear() else DetectorStatus.warning(),
                ),
                CustomRomHeaderFactModel(
                    label = "Build",
                    value = signalValue(report.buildSignalCount),
                    status = if (report.buildSignalCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
                ),
                CustomRomHeaderFactModel(
                    label = "Runtime",
                    value = when {
                        report.runtimeSignalCount > 0 -> report.runtimeSignalCount.toString()
                        report.packageVisibility == CustomRomPackageVisibility.RESTRICTED -> "Scoped"
                        else -> "None"
                    },
                    status = when {
                        report.runtimeSignalCount > 0 -> DetectorStatus.warning()
                        report.packageVisibility == CustomRomPackageVisibility.RESTRICTED -> DetectorStatus.info(
                            InfoKind.SUPPORT
                        )

                        else -> DetectorStatus.allClear()
                    },
                ),
                CustomRomHeaderFactModel(
                    label = "Native",
                    value = when {
                        !report.nativeAvailable -> "N/A"
                        report.nativeSignalCount > 0 -> report.nativeSignalCount.toString()
                        else -> "None"
                    },
                    status = when {
                        report.nativeSignalCount > 0 -> DetectorStatus.warning()
                        !report.nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.allClear()
                    },
                ),
            )
        }
    }

    private fun buildBuildRows(report: CustomRomReport): List<CustomRomDetailRowModel> {
        return when (report.stage) {
            CustomRomStage.LOADING -> placeholderRows(
                labels = listOf("System properties", "Build fields"),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
            )

            CustomRomStage.FAILED -> placeholderRows(
                labels = listOf("System properties", "Build fields"),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
            )

            CustomRomStage.READY -> buildList {
                if (report.propertyFindings.isEmpty()) {
                    add(
                        CustomRomDetailRowModel(
                            label = "System properties",
                            value = "Clean",
                            status = DetectorStatus.allClear(),
                        ),
                    )
                } else {
                    addAll(report.propertyFindings.map(::findingRow))
                }

                if (report.buildFindings.isEmpty()) {
                    add(
                        CustomRomDetailRowModel(
                            label = "Build fields",
                            value = "Clean",
                            status = DetectorStatus.allClear(),
                        ),
                    )
                } else {
                    addAll(report.buildFindings.map(::findingRow))
                }
            }
        }
    }

    private fun buildRuntimeRows(report: CustomRomReport): List<CustomRomDetailRowModel> {
        return when (report.stage) {
            CustomRomStage.LOADING -> placeholderRows(
                labels = listOf("Packages", "Services", "Reflection"),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
            )

            CustomRomStage.FAILED -> placeholderRows(
                labels = listOf("Packages", "Services", "Reflection"),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
            )

            CustomRomStage.READY -> buildList {
                if (report.packageFindings.isEmpty()) {
                    add(
                        CustomRomDetailRowModel(
                            label = "Packages",
                            value = if (report.packageVisibility == CustomRomPackageVisibility.RESTRICTED) "Scoped" else "Clean",
                            status = if (report.packageVisibility == CustomRomPackageVisibility.RESTRICTED) {
                                DetectorStatus.info(InfoKind.SUPPORT)
                            } else {
                                DetectorStatus.allClear()
                            },
                            detail = if (report.packageVisibility == CustomRomPackageVisibility.RESTRICTED) {
                                "Package visibility looked restricted, so clean package results may under-report ROM apps."
                            } else {
                                null
                            },
                        ),
                    )
                } else {
                    addAll(report.packageFindings.map(::findingRow))
                }

                if (report.serviceFindings.isEmpty()) {
                    add(
                        CustomRomDetailRowModel(
                            label = "Services",
                            value = "Clean",
                            status = DetectorStatus.allClear(),
                            detail = "Listed ${report.listedServiceCount} services.",
                        ),
                    )
                } else {
                    addAll(report.serviceFindings.map(::findingRow))
                }

                if (report.reflectionFindings.isEmpty()) {
                    add(
                        CustomRomDetailRowModel(
                            label = "Reflection",
                            value = "Clean",
                            status = DetectorStatus.allClear(),
                        ),
                    )
                } else {
                    addAll(report.reflectionFindings.map(::findingRow))
                }
            }
        }
    }

    private fun buildFrameworkRows(report: CustomRomReport): List<CustomRomDetailRowModel> {
        return when (report.stage) {
            CustomRomStage.LOADING -> placeholderRows(
                labels = listOf(
                    "Resource maps",
                    "Platform files",
                    "Recovery scripts",
                    "SELinux policy",
                    "Product overlays"
                ),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
            )

            CustomRomStage.FAILED -> placeholderRows(
                labels = listOf(
                    "Resource maps",
                    "Platform files",
                    "Recovery scripts",
                    "SELinux policy",
                    "Product overlays"
                ),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
            )

            CustomRomStage.READY -> buildList {
                if (report.resourceInjectionFindings.isEmpty()) {
                    add(
                        CustomRomDetailRowModel(
                            "Resource maps",
                            "Clean",
                            DetectorStatus.allClear()
                        )
                    )
                } else {
                    addAll(report.resourceInjectionFindings.map(::findingRow))
                }

                if (report.platformFileFindings.isEmpty()) {
                    add(
                        CustomRomDetailRowModel(
                            "Platform files",
                            "Clean",
                            DetectorStatus.allClear()
                        )
                    )
                } else {
                    addAll(report.platformFileFindings.map(::findingRow))
                }

                if (report.recoveryScripts.isEmpty()) {
                    add(
                        CustomRomDetailRowModel(
                            "Recovery scripts",
                            "Clean",
                            DetectorStatus.allClear()
                        )
                    )
                } else {
                    addAll(
                        report.recoveryScripts.map { script ->
                            CustomRomDetailRowModel(
                                label = script.substringAfterLast('/'),
                                value = "Custom ROM",
                                status = DetectorStatus.warning(),
                                detail = script,
                                detailMonospace = true,
                            )
                        },
                    )
                }

                if (report.policyFindings.isEmpty()) {
                    add(
                        CustomRomDetailRowModel(
                            "SELinux policy",
                            "Clean",
                            DetectorStatus.allClear()
                        )
                    )
                } else {
                    addAll(report.policyFindings.map(::findingRow))
                }

                if (report.overlayFindings.isEmpty()) {
                    add(
                        CustomRomDetailRowModel(
                            "Product overlays",
                            "Clean",
                            DetectorStatus.allClear()
                        )
                    )
                } else {
                    addAll(report.overlayFindings.map(::findingRow))
                }
            }
        }
    }

    private fun buildImpactItems(report: CustomRomReport): List<CustomRomImpactItemModel> {
        return when (report.stage) {
            CustomRomStage.LOADING -> listOf(
                CustomRomImpactItemModel(
                    text = "Gathering local firmware branding and framework evidence.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            CustomRomStage.FAILED -> listOf(
                CustomRomImpactItemModel(
                    text = report.errorMessage ?: "Custom ROM scan failed.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            CustomRomStage.READY -> when {
                report.hasIndicators -> buildList {
                    add(
                        CustomRomImpactItemModel(
                            text = "Aftermarket firmware can legitimately alter build properties, privileged services, and security defaults.",
                            status = DetectorStatus.warning(),
                        ),
                    )
                    add(
                        CustomRomImpactItemModel(
                            text = "Attestation behavior, Play Integrity, and some banking or DRM apps may differ on custom ROMs.",
                            status = DetectorStatus.warning(),
                        ),
                    )
                    add(
                        CustomRomImpactItemModel(
                            text = "This signal alone does not prove malicious compromise or active root access.",
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                        ),
                    )
                }

                else -> buildList {
                    add(
                        CustomRomImpactItemModel(
                            text = "No common aftermarket firmware branding or framework traces were found.",
                            status = DetectorStatus.allClear(),
                        ),
                    )
                    if (report.packageVisibility == CustomRomPackageVisibility.RESTRICTED) {
                        add(
                            CustomRomImpactItemModel(
                                text = "Package visibility was scoped, so clean app-level evidence may be incomplete.",
                                status = DetectorStatus.info(InfoKind.SUPPORT),
                            ),
                        )
                    }
                    add(
                        CustomRomImpactItemModel(
                            text = "A determined ROM can remove obvious signatures, so absence is not proof of stock firmware.",
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                        ),
                    )
                }
            }
        }
    }

    private fun buildMethodRows(report: CustomRomReport): List<CustomRomDetailRowModel> {
        return when (report.stage) {
            CustomRomStage.LOADING -> placeholderRows(
                labels = listOf(
                    "propertyScan",
                    "buildFieldScan",
                    "packageScan",
                    "serviceScan",
                    "reflectionScan",
                    "mapsInjection",
                    "nativeFiles",
                    "nativePolicy",
                    "nativeLibrary",
                ),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
            )

            CustomRomStage.FAILED -> placeholderRows(
                labels = listOf(
                    "propertyScan",
                    "buildFieldScan",
                    "packageScan",
                    "serviceScan",
                    "reflectionScan",
                    "mapsInjection",
                    "nativeFiles",
                    "nativePolicy",
                    "nativeLibrary",
                ),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Failed",
            )

            CustomRomStage.READY -> report.methods.map { result ->
                CustomRomDetailRowModel(
                    label = result.label,
                    value = result.summary,
                    status = methodStatus(result),
                    detail = result.detail,
                    detailMonospace = true,
                )
            }
        }
    }

    private fun buildScanRows(report: CustomRomReport): List<CustomRomDetailRowModel> {
        return when (report.stage) {
            CustomRomStage.LOADING -> placeholderRows(
                labels = listOf(
                    "Properties checked",
                    "Build fields checked",
                    "Packages checked",
                    "Package visibility",
                    "Named services checked",
                    "Services listed",
                    "Native library",
                ),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
            )

            CustomRomStage.FAILED -> placeholderRows(
                labels = listOf(
                    "Properties checked",
                    "Build fields checked",
                    "Packages checked",
                    "Package visibility",
                    "Named services checked",
                    "Services listed",
                    "Native library",
                ),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
            )

            CustomRomStage.READY -> listOf(
                CustomRomDetailRowModel(
                    label = "Properties checked",
                    value = report.checkedPropertyCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                CustomRomDetailRowModel(
                    label = "Build fields checked",
                    value = report.checkedBuildFieldCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                CustomRomDetailRowModel(
                    label = "Packages checked",
                    value = report.checkedPackageCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                CustomRomDetailRowModel(
                    label = "Package visibility",
                    value = if (report.packageVisibility == CustomRomPackageVisibility.FULL) "Full" else "Scoped",
                    status = if (report.packageVisibility == CustomRomPackageVisibility.FULL) {
                        DetectorStatus.allClear()
                    } else {
                        DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                CustomRomDetailRowModel(
                    label = "Named services checked",
                    value = report.checkedServiceCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                CustomRomDetailRowModel(
                    label = "Services listed",
                    value = report.listedServiceCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                CustomRomDetailRowModel(
                    label = "Native library",
                    value = if (report.nativeAvailable) "Loaded" else "Unavailable",
                    status = if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
            )
        }
    }

    private fun findingRow(
        finding: CustomRomFinding,
    ): CustomRomDetailRowModel {
        return CustomRomDetailRowModel(
            label = finding.signal,
            value = finding.romName,
            status = DetectorStatus.warning(),
            detail = finding.detail,
            detailMonospace = true,
        )
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus,
    ): List<CustomRomHeaderFactModel> {
        return listOf(
            CustomRomHeaderFactModel("ROMs", value, status),
            CustomRomHeaderFactModel("Build", value, status),
            CustomRomHeaderFactModel("Runtime", value, status),
            CustomRomHeaderFactModel("Native", value, status),
        )
    }

    private fun placeholderRows(
        labels: List<String>,
        status: DetectorStatus,
        value: String,
    ): List<CustomRomDetailRowModel> {
        return labels.map { label ->
            CustomRomDetailRowModel(
                label = label,
                value = value,
                status = status,
            )
        }
    }

    private fun detectedRomValue(report: CustomRomReport): String {
        return when {
            report.detectedRoms.isEmpty() -> "None"
            report.detectedRoms.size <= 2 -> report.detectedRoms.joinToString("/")
            else -> report.detectedRoms.take(2)
                .joinToString("/") + " +${report.detectedRoms.size - 2}"
        }
    }

    private fun signalValue(count: Int): String {
        return if (count > 0) count.toString() else "None"
    }

    private fun methodStatus(result: CustomRomMethodResult): DetectorStatus {
        return when (result.outcome) {
            CustomRomMethodOutcome.CLEAN -> DetectorStatus.allClear()
            CustomRomMethodOutcome.DETECTED -> DetectorStatus.warning()
            CustomRomMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun CustomRomReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            CustomRomStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            CustomRomStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            CustomRomStage.READY -> if (hasIndicators) {
                DetectorStatus.warning()
            } else {
                DetectorStatus.allClear()
            }
        }
    }
}
