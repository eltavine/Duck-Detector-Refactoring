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
import com.eltavine.duckdetector.features.customrom.domain.CustomRomModificationFinding
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
            CustomRomStage.LOADING -> "properties + prop integrity + packages + services + native traces"
            CustomRomStage.FAILED -> "local aftermarket firmware probe failed"
            CustomRomStage.READY -> buildString {
                append("${report.checkedPropertyCount} props · ")
                if (report.propertyAreaAvailable) {
                    append("${report.checkedModificationPropertyCount} mod props")
                } else {
                    append("mod props unavailable")
                }
                append(" · ${report.checkedPackageCount} packages · ${report.checkedServiceCount} named services")
            }
        }
    }

    private fun buildVerdict(report: CustomRomReport): String {
        return when (report.stage) {
            CustomRomStage.LOADING -> "Scanning aftermarket firmware signals"
            CustomRomStage.FAILED -> "Custom ROM scan failed"
            CustomRomStage.READY -> buildVerdictBody(report)
        }
    }

    private fun buildSummary(report: CustomRomReport): String {
        return when (report.stage) {
            CustomRomStage.LOADING ->
                "System properties, prop integrity, runtime packages/services, framework traces, and resource map checks are collecting local firmware evidence."

            CustomRomStage.FAILED ->
                report.errorMessage ?: "Custom ROM scan failed before evidence could be assembled."

            CustomRomStage.READY -> when {
                report.hasIndicators ->
                    "Build properties, property-area integrity, bootloader state, runtime packages or services, framework traces, native symbol traces, or resource map anomalies indicate aftermarket firmware, resetprop-style changes, or an unlocked boot chain."

                !report.nativeAvailable ->
                    "Native coverage was unavailable on this build, so only Java-side probes were used."

                report.hasReducedCoverage() ->
                    "Available probes were clean, but package visibility, property-area, or native symbol coverage was incomplete on this build."

                else ->
                    "No common custom ROM branding, property-area, service, package, framework trace, native symbol trace, or resource map anomaly surfaced from local probes."
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
                    status = when {
                        report.detectedRoms.isNotEmpty() -> DetectorStatus.warning()
                        report.hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.allClear()
                    },
                ),
                CustomRomHeaderFactModel(
                    label = "Build",
                    value = when {
                        report.buildSignalCount + report.modificationSignalCount > 0 ->
                            signalValue(report.buildSignalCount + report.modificationSignalCount)

                        !report.propertyAreaAvailable -> "Unavailable"

                        else -> "None"
                    },
                    status = when {
                        report.buildSignalCount + report.modificationSignalCount > 0 ->
                            DetectorStatus.warning()

                        !report.propertyAreaAvailable -> DetectorStatus.info(InfoKind.SUPPORT)

                        else -> DetectorStatus.allClear()
                    },
                ),
                CustomRomHeaderFactModel(
                    label = "Runtime",
                    value = when {
                        report.runtimeSignalCount > 0 -> report.runtimeSignalCount.toString()
                        report.packageVisibility == CustomRomPackageVisibility.RESTRICTED -> "Scoped"
                        report.packageVisibility == CustomRomPackageVisibility.UNKNOWN -> "Unavailable"
                        else -> "None"
                    },
                    status = when {
                        report.runtimeSignalCount > 0 -> DetectorStatus.warning()
                        report.packageVisibility != CustomRomPackageVisibility.FULL -> DetectorStatus.info(
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
                        report.hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
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

                if (report.modificationFindings.isEmpty()) {
                    add(
                        CustomRomDetailRowModel(
                            label = "Modification",
                            value = if (report.propertyAreaAvailable) "Clean" else "Unavailable",
                            status = if (report.propertyAreaAvailable) {
                                DetectorStatus.allClear()
                            } else {
                                DetectorStatus.info(InfoKind.SUPPORT)
                            },
                            detail = if (report.propertyAreaAvailable) {
                                buildCleanModificationDetail(report)
                            } else {
                                "Native property-area coverage was unavailable on this build."
                            },
                        ),
                    )
                } else {
                    addAll(report.modificationFindings.map(::modificationFindingRow))
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
                            value = when (report.packageVisibility) {
                                CustomRomPackageVisibility.FULL -> "Clean"
                                CustomRomPackageVisibility.RESTRICTED -> "Scoped"
                                CustomRomPackageVisibility.UNKNOWN -> "Unavailable"
                            },
                            status = if (report.packageVisibility != CustomRomPackageVisibility.FULL) {
                                DetectorStatus.info(InfoKind.SUPPORT)
                            } else {
                                DetectorStatus.allClear()
                            },
                            detail = when (report.packageVisibility) {
                                CustomRomPackageVisibility.RESTRICTED ->
                                    "Package visibility was restricted, so clean package results may under-report ROM apps."
                                CustomRomPackageVisibility.UNKNOWN ->
                                    "Package inventory was unavailable or anomalous, so package absence is inconclusive."
                                CustomRomPackageVisibility.FULL -> null
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
                    "Native symbols",
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
                    "Native symbols",
                    "Product overlays"
                ),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
            )

            CustomRomStage.READY -> buildList {
                if (!report.nativeAvailable) {
                    addUnavailableFrameworkRow("Resource maps")
                    addUnavailableFrameworkRow("Platform files")
                    addUnavailableFrameworkRow("Recovery scripts")
                    addUnavailableFrameworkRow("SELinux policy")
                    addUnavailableFrameworkRow("Native symbols")
                    addUnavailableFrameworkRow("Product overlays")
                    return@buildList
                }

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

                if (report.symbolFindings.isEmpty()) {
                    add(
                        if (report.symbolScanAvailable) {
                            CustomRomDetailRowModel(
                                "Native symbols",
                                "Clean",
                                DetectorStatus.allClear()
                            )
                        } else {
                            CustomRomDetailRowModel(
                                "Native symbols",
                                "Unsupported",
                                DetectorStatus.info(InfoKind.SUPPORT),
                                detail = "Native symbol trace detection only runs on Android 10+.",
                            )
                        }
                    )
                } else {
                    addAll(report.symbolFindings.map(::findingRow))
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
                            text = "Aftermarket firmware can legitimately alter build properties, property storage, bootloader state, privileged services, and security defaults.",
                            status = DetectorStatus.warning(),
                        ),
                    )
                    add(
                        CustomRomImpactItemModel(
                            text = "Attestation behavior, Play Integrity, and some banking or DRM apps may differ on custom ROMs or modified boot chains.",
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
                    if (!report.nativeAvailable) {
                        add(
                            CustomRomImpactItemModel(
                                text = "Native coverage was unavailable on this build, so clean native trace results are not available.",
                                status = DetectorStatus.info(InfoKind.SUPPORT),
                            ),
                        )
                    } else if (report.hasReducedCoverage()) {
                        add(
                            CustomRomImpactItemModel(
                                text = "No custom ROM signature surfaced from available probes, but package visibility, property-area, or native symbol coverage was incomplete.",
                                status = DetectorStatus.info(InfoKind.SUPPORT),
                            ),
                        )
                    } else {
                        add(
                            CustomRomImpactItemModel(
                                text = "No common aftermarket firmware branding, property-area, or framework traces were found.",
                                status = DetectorStatus.allClear(),
                            ),
                        )
                    }
                    if (report.packageVisibility != CustomRomPackageVisibility.FULL) {
                        add(
                            CustomRomImpactItemModel(
                                text = if (report.packageVisibility == CustomRomPackageVisibility.RESTRICTED) {
                                    "Package visibility was scoped, so clean app-level evidence may be incomplete."
                                } else {
                                    "Package inventory was unavailable or anomalous, so app-level absence is inconclusive."
                                },
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
                    "modificationScan",
                    "packageScan",
                    "serviceScan",
                    "reflectionScan",
                    "mapsInjection",
                    "nativeFiles",
                    "nativePolicy",
                    "nativeSymbols",
                    "nativeLibrary",
                ),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
            )

            CustomRomStage.FAILED -> placeholderRows(
                labels = listOf(
                    "propertyScan",
                    "buildFieldScan",
                    "modificationScan",
                    "packageScan",
                    "serviceScan",
                    "reflectionScan",
                    "mapsInjection",
                    "nativeFiles",
                    "nativePolicy",
                    "nativeSymbols",
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
                    "Modification props checked",
                    "Prop area contexts",
                    "Prop area anomalies",
                    "Prop item anomalies",
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
                    "Modification props checked",
                    "Prop area contexts",
                    "Prop area anomalies",
                    "Prop item anomalies",
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
                    label = "Modification props checked",
                    value = if (report.propertyAreaAvailable) {
                        report.checkedModificationPropertyCount.toString()
                    } else {
                        "Unavailable"
                    },
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                    detail = if (report.propertyAreaAvailable) {
                        null
                    } else {
                        "Native property-area coverage was unavailable on this build."
                    },
                ),
                CustomRomDetailRowModel(
                    label = "Prop area contexts",
                    value = if (report.propertyAreaAvailable) {
                        report.propertyAreaContextCount.toString()
                    } else {
                        "Unavailable"
                    },
                    status = if (report.propertyAreaAvailable) {
                        if (report.propertyAreaContextCount > 0) {
                            DetectorStatus.allClear()
                        } else {
                            DetectorStatus.info(InfoKind.SUPPORT)
                        }
                    } else {
                        DetectorStatus.info(InfoKind.SUPPORT)
                    },
                    detail = if (report.propertyAreaAvailable) {
                        null
                    } else {
                        "Native property-area coverage was unavailable on this build."
                    },
                ),
                CustomRomDetailRowModel(
                    label = "Prop area anomalies",
                    value = if (report.propertyAreaAvailable) {
                        report.propertyAreaAnomalyCount.toString()
                    } else {
                        "Unavailable"
                    },
                    status = if (report.propertyAreaAvailable) {
                        if (report.propertyAreaAnomalyCount > 0) {
                            DetectorStatus.warning()
                        } else {
                            DetectorStatus.allClear()
                        }
                    } else {
                        DetectorStatus.info(InfoKind.SUPPORT)
                    },
                    detail = if (report.propertyAreaAvailable) {
                        null
                    } else {
                        "Native property-area coverage was unavailable on this build."
                    },
                ),
                CustomRomDetailRowModel(
                    label = "Prop item anomalies",
                    value = if (report.propertyAreaAvailable) {
                        report.propertyAreaItemAnomalyCount.toString()
                    } else {
                        "Unavailable"
                    },
                    status = if (report.propertyAreaAvailable) {
                        if (report.propertyAreaItemAnomalyCount > 0) {
                            DetectorStatus.warning()
                        } else {
                            DetectorStatus.allClear()
                        }
                    } else {
                        DetectorStatus.info(InfoKind.SUPPORT)
                    },
                    detail = if (report.propertyAreaAvailable) {
                        null
                    } else {
                        "Native property-area coverage was unavailable on this build."
                    },
                ),
                CustomRomDetailRowModel(
                    label = "Packages checked",
                    value = report.checkedPackageCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                CustomRomDetailRowModel(
                    label = "Package visibility",
                    value = when (report.packageVisibility) {
                        CustomRomPackageVisibility.FULL -> "Full"
                        CustomRomPackageVisibility.RESTRICTED -> "Scoped"
                        CustomRomPackageVisibility.UNKNOWN -> "Unknown"
                    },
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

    private fun modificationFindingRow(
        finding: CustomRomModificationFinding,
    ): CustomRomDetailRowModel {
        return CustomRomDetailRowModel(
            label = finding.signal,
            value = finding.summary,
            status = DetectorStatus.warning(),
            detail = "${finding.category}: ${finding.detail}",
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

    private fun buildCleanModificationDetail(report: CustomRomReport): String {
        return buildString {
            append("Tracked property area, serial, and residual value checks were clean")
            if (report.checkedModificationPropertyCount > 0 || report.propertyAreaContextCount > 0) {
                append("; checked ")
                if (report.checkedModificationPropertyCount > 0) {
                    append(report.checkedModificationPropertyCount)
                    append(" tracked property name(s)")
                } else {
                    append("tracked property names")
                }
            }
            if (report.propertyAreaContextCount > 0) {
                append(" across ")
                append(report.propertyAreaContextCount)
                append(" property-area context(s)")
            }
            append('.')
        }
    }

    private fun buildVerdictBody(report: CustomRomReport): String {
        val verdictParts = buildList {
            if (report.detectedRoms.isNotEmpty()) {
                add(
                    if (report.detectedRoms.size == 1) {
                        "${report.detectedRoms.first()} signature"
                    } else {
                        "${report.detectedRoms.size} ROM signatures"
                    }
                )
            }
            if (report.modificationFindings.isNotEmpty()) {
                add("${report.modificationFindings.size} modification signal(s)")
            }
            if (report.symbolFindings.isNotEmpty()) {
                add("${report.symbolFindings.size} native symbol trace(s)")
            }
        }

        return when {
            verdictParts.isNotEmpty() -> "${verdictParts.joinToString(separator = " + ")} detected"
            report.hasReducedCoverage() -> "Custom ROM scan has reduced coverage"
            else -> "No custom ROM signatures"
        }
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
            CustomRomStage.READY -> when {
                hasIndicators -> DetectorStatus.warning()
                hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                else -> DetectorStatus.allClear()
            }
        }
    }

    private fun MutableList<CustomRomDetailRowModel>.addUnavailableFrameworkRow(label: String) {
        add(
            CustomRomDetailRowModel(
                label = label,
                value = "Unavailable",
                status = DetectorStatus.info(InfoKind.SUPPORT),
                detail = "Native framework trace coverage was unavailable on this build.",
            )
        )
    }

    private fun CustomRomReport.hasReducedCoverage(): Boolean {
        return !nativeAvailable ||
                !propertyAreaAvailable ||
                !symbolScanAvailable ||
                packageVisibility != CustomRomPackageVisibility.FULL
    }
}
