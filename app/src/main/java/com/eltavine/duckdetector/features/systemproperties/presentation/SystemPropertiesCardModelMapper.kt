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

package com.eltavine.duckdetector.features.systemproperties.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodOutcome
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodResult
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesReport
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesStage
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySignal
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySource
import com.eltavine.duckdetector.features.systemproperties.ui.model.SystemPropertiesCardModel
import com.eltavine.duckdetector.features.systemproperties.ui.model.SystemPropertiesDetailRowModel
import com.eltavine.duckdetector.features.systemproperties.ui.model.SystemPropertiesHeaderFactModel
import com.eltavine.duckdetector.features.systemproperties.ui.model.SystemPropertiesImpactItemModel

class SystemPropertiesCardModelMapper {

    fun map(
        report: SystemPropertiesReport,
    ): SystemPropertiesCardModel {
        return SystemPropertiesCardModel(
            title = "System Properties",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            coreRows = buildCoreRows(report),
            bootRows = buildBootRows(report),
            buildRows = buildBuildRows(report),
            sourceRows = buildSourceRows(report),
            consistencyRows = buildConsistencyRows(report),
            infoRows = buildInfoRows(report),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }

    private fun buildSubtitle(report: SystemPropertiesReport): String {
        return when (report.stage) {
            SystemPropertiesStage.LOADING -> "security props + raw boot + source cross-checks"
            SystemPropertiesStage.FAILED -> "local property scan failed"
            SystemPropertiesStage.READY -> buildString {
                append("${report.checkedRuleCount} rules · ${report.infoPropertyCount} info · ${report.nativeHitCount} native · ${report.buildSignalCount} Build")
                if (report.readOnlySerialFindingCount > 0) {
                    append(" · ${report.readOnlySerialFindingCount} ro-serial anomaly(s)")
                }
                if (report.propAreaHoleCount > 0) {
                    append(" · ${report.propAreaHoleCount} prop-area hole(s)")
                }
            }
        }
    }

    private fun buildVerdict(report: SystemPropertiesReport): String {
        return when (report.stage) {
            SystemPropertiesStage.LOADING -> "Scanning property, boot, and source state"
            SystemPropertiesStage.FAILED -> "System Properties scan failed"
            SystemPropertiesStage.READY -> when {
                report.hasDangerSignals -> "${report.dangerSignals.size} high-risk property or coherence signal(s)"
                report.hasWarningSignals -> "${report.warningSignals.size} property signal(s) need review"
                else -> "No risky property or coherence drift"
            }
        }
    }

    private fun buildSummary(report: SystemPropertiesReport): String {
        return when (report.stage) {
            SystemPropertiesStage.LOADING ->
                "Core security, verified boot, build profile, source consistency, and raw boot cross-checks are collecting local evidence."

            SystemPropertiesStage.FAILED ->
                report.errorMessage
                    ?: "System property scan failed before evidence could be assembled."

            SystemPropertiesStage.READY -> when {
                report.hasDangerSignals ->
                    "Property values, raw boot contradictions, read-only property serial anomalies, cross-source drift, or raw property-area residue indicate insecure build state, spoofing risk, or modified boot context."

                report.hasWarningSignals ->
                    "Cross-source drift, cross-property drift, read-only property serial anomalies, or raw property-area residue suggests a review-worthy build or boot context, even if not every warning means active compromise."

                else ->
                    "Key properties, framework constants, native libc reads, raw boot parameters, and property-area layout stayed aligned."
            }
        }
    }

    private fun buildHeaderFacts(report: SystemPropertiesReport): List<SystemPropertiesHeaderFactModel> {
        return when (report.stage) {
            SystemPropertiesStage.LOADING -> placeholderFacts(
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            SystemPropertiesStage.FAILED -> placeholderFacts(
                "Error",
                DetectorStatus.info(InfoKind.ERROR)
            )

            SystemPropertiesStage.READY -> {
                val bootSignals = report.signals.filter {
                    it.category == SystemPropertyCategory.VERIFIED_BOOT ||
                            it.category == SystemPropertyCategory.PARTITION_VERITY
                }
                val buildSignals = report.signals.filter {
                    it.category == SystemPropertyCategory.BUILD_PROFILE
                }
                listOf(
                    SystemPropertiesHeaderFactModel(
                        label = "Critical",
                        value = countLabel(report.dangerSignals.size),
                        status = if (report.dangerSignals.isEmpty()) DetectorStatus.allClear() else DetectorStatus.danger(),
                    ),
                    SystemPropertiesHeaderFactModel(
                        label = "Review",
                        value = countLabel(report.warningSignals.size),
                        status = if (report.warningSignals.isEmpty()) DetectorStatus.allClear() else DetectorStatus.warning(),
                    ),
                    SystemPropertiesHeaderFactModel(
                        label = "Boot",
                        value = if (report.bootSignalCount > 0) report.bootSignalCount.toString() else "Clean",
                        status = categoryStatus(bootSignals),
                    ),
                    SystemPropertiesHeaderFactModel(
                        label = "Build",
                        value = if (report.buildProfileSignalCount > 0) report.buildProfileSignalCount.toString() else "Clean",
                        status = categoryStatus(buildSignals),
                    ),
                )
            }
        }
    }

    private fun buildCoreRows(report: SystemPropertiesReport): List<SystemPropertiesDetailRowModel> {
        return when (report.stage) {
            SystemPropertiesStage.LOADING -> placeholderRows(
                labels = listOf(
                    "ro.secure",
                    "ro.debuggable",
                    "service.adb.root",
                    "init.svc.magisk_daemon"
                ),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
            )

            SystemPropertiesStage.FAILED -> placeholderRows(
                labels = listOf(
                    "ro.secure",
                    "ro.debuggable",
                    "service.adb.root",
                    "init.svc.magisk_daemon"
                ),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
            )

            SystemPropertiesStage.READY -> report.signals.filter {
                it.category == SystemPropertyCategory.SECURITY_CORE ||
                        it.category == SystemPropertyCategory.ROOT_RUNTIME ||
                        it.category == SystemPropertyCategory.CUSTOM_ROM
            }.sortedBy { it.property }
                .map(::signalRow)
        }
    }

    private fun buildBootRows(report: SystemPropertiesReport): List<SystemPropertiesDetailRowModel> {
        return when (report.stage) {
            SystemPropertiesStage.LOADING -> placeholderRows(
                labels = listOf(
                    "ro.boot.verifiedbootstate",
                    "ro.boot.flash.locked",
                    "partition.system.verified"
                ),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
            )

            SystemPropertiesStage.FAILED -> placeholderRows(
                labels = listOf(
                    "ro.boot.verifiedbootstate",
                    "ro.boot.flash.locked",
                    "partition.system.verified"
                ),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
            )

            SystemPropertiesStage.READY -> report.signals.filter {
                it.category == SystemPropertyCategory.VERIFIED_BOOT ||
                        it.category == SystemPropertyCategory.PARTITION_VERITY
            }.sortedBy { it.property }
                .map(::signalRow)
        }
    }

    private fun buildBuildRows(report: SystemPropertiesReport): List<SystemPropertiesDetailRowModel> {
        return when (report.stage) {
            SystemPropertiesStage.LOADING -> placeholderRows(
                labels = listOf(
                    "ro.build.type",
                    "ro.build.tags",
                    "Build.TAGS",
                    "Build.FINGERPRINT"
                ),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
            )

            SystemPropertiesStage.FAILED -> placeholderRows(
                labels = listOf(
                    "ro.build.type",
                    "ro.build.tags",
                    "Build.TAGS",
                    "Build.FINGERPRINT"
                ),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
            )

            SystemPropertiesStage.READY -> report.signals.filter {
                it.category == SystemPropertyCategory.BUILD_PROFILE
            }.sortedBy { it.property }
                .map(::signalRow)
        }
    }

    private fun buildSourceRows(report: SystemPropertiesReport): List<SystemPropertiesDetailRowModel> {
        return when (report.stage) {
            SystemPropertiesStage.LOADING -> placeholderRows(
                labels = listOf("ro.boot.verifiedbootstate", "ro.build.type"),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
                monospace = true,
            )

            SystemPropertiesStage.FAILED -> placeholderRows(
                labels = listOf("ro.boot.verifiedbootstate", "ro.build.type"),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
                monospace = true,
            )

            SystemPropertiesStage.READY -> report.signals.filter {
                it.category == SystemPropertyCategory.SOURCE_CONSISTENCY
            }.sortedBy { it.property }
                .map(::signalRow)
        }
    }

    private fun buildConsistencyRows(report: SystemPropertiesReport): List<SystemPropertiesDetailRowModel> {
        return when (report.stage) {
            SystemPropertiesStage.LOADING -> placeholderRows(
                labels = listOf(
                    "Verified boot coherence",
                    "Build.TYPE <> fingerprint tail",
                    "ro serial anomaly: ro.build.fingerprint",
                    "prop_area hole: u:object_r:shell_prop:s0"
                ),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
                monospace = true,
            )

            SystemPropertiesStage.FAILED -> placeholderRows(
                labels = listOf(
                    "Verified boot coherence",
                    "Build.TYPE <> fingerprint tail",
                    "ro serial anomaly: ro.build.fingerprint",
                    "prop_area hole: u:object_r:shell_prop:s0"
                ),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
                monospace = true,
            )

            SystemPropertiesStage.READY -> report.signals.filter {
                it.category == SystemPropertyCategory.PROPERTY_CONSISTENCY
            }.sortedBy { it.property }
                .map(::signalRow)
        }
    }

    private fun buildInfoRows(report: SystemPropertiesReport): List<SystemPropertiesDetailRowModel> {
        return when (report.stage) {
            SystemPropertiesStage.LOADING -> placeholderRows(
                labels = listOf(
                    "ro.product.model",
                    "ro.build.version.security_patch",
                    "ro.build.fingerprint"
                ),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
                monospace = true,
            )

            SystemPropertiesStage.FAILED -> placeholderRows(
                labels = listOf(
                    "ro.product.model",
                    "ro.build.version.security_patch",
                    "ro.build.fingerprint"
                ),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
                monospace = true,
            )

            SystemPropertiesStage.READY -> report.infoSignals.sortedBy { it.property }
                .map(::infoRow)
        }
    }

    private fun buildImpactItems(report: SystemPropertiesReport): List<SystemPropertiesImpactItemModel> {
        return when (report.stage) {
            SystemPropertiesStage.LOADING -> listOf(
                SystemPropertiesImpactItemModel(
                    text = "Gathering property, boot, and native cross-check evidence.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            SystemPropertiesStage.FAILED -> listOf(
                SystemPropertiesImpactItemModel(
                    text = report.errorMessage ?: "System Properties scan failed.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            SystemPropertiesStage.READY -> buildList {
                val crossCheckSignals = report.signals.filter(::isCrossCheckSignal)
                if (crossCheckSignals.isNotEmpty()) {
                    add(
                        SystemPropertiesImpactItemModel(
                            text = "Cross-check contradictions mean different system layers disagree about the same boot or build state, which is stronger than a single suspicious value.",
                            status = if (crossCheckSignals.any { it.severity == SystemPropertySeverity.DANGER }) {
                                DetectorStatus.danger()
                            } else {
                                DetectorStatus.warning()
                            },
                        ),
                    )
                }
                if (report.readOnlySerialFindingCount > 0) {
                    add(
                        SystemPropertiesImpactItemModel(
                            text = "A non-zero low-24 update field on stable ro.* properties means a write-once property appears to have been modified after init, which is stronger than an ordinary value mismatch.",
                            status = if (report.dangerSignals.any(::isReadOnlySerialSignal)) {
                                DetectorStatus.danger()
                            } else {
                                DetectorStatus.warning()
                            },
                        ),
                    )
                }
                if (report.propAreaHoleCount > 0) {
                    add(
                        SystemPropertiesImpactItemModel(
                            text = "Raw /dev/__properties__ hole residue means the property storage layout no longer matches a normal append-only allocation pattern.",
                            status = if (report.dangerSignals.any(::isPropAreaHoleSignal)) {
                                DetectorStatus.danger()
                            } else {
                                DetectorStatus.warning()
                            },
                        ),
                    )
                }
                if (report.sourceMismatchCount > 0) {
                    add(
                        SystemPropertiesImpactItemModel(
                            text = "Different property APIs returned different values. That can indicate hook-based spoofing, translation issues, or framework/native drift.",
                            status = if (report.dangerSignals.any { it.category == SystemPropertyCategory.SOURCE_CONSISTENCY }) {
                                DetectorStatus.danger()
                            } else {
                                DetectorStatus.warning()
                            },
                        ),
                    )
                }
                if (isEmpty()) {
                    add(
                        SystemPropertiesImpactItemModel(
                            text = "Observed key properties matched conservative production expectations across multiple read paths.",
                            status = DetectorStatus.allClear(),
                        ),
                    )
                }
                add(
                    SystemPropertiesImpactItemModel(
                        text = "System properties are still software-readable values, so even aligned results should be combined with kernel, SU, TEE, and package-level signals.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )
            }
        }
    }

    private fun buildMethodRows(report: SystemPropertiesReport): List<SystemPropertiesDetailRowModel> {
        return when (report.stage) {
            SystemPropertiesStage.LOADING -> placeholderMethodRows(
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pending"
            )

            SystemPropertiesStage.FAILED -> placeholderMethodRows(
                DetectorStatus.info(InfoKind.ERROR),
                "Failed"
            )

            SystemPropertiesStage.READY -> report.methods.map { result ->
                SystemPropertiesDetailRowModel(
                    label = result.label,
                    value = result.summary,
                    status = methodStatus(result),
                    detail = result.detail,
                    detailMonospace = true,
                )
            }
        }
    }

    private fun buildScanRows(report: SystemPropertiesReport): List<SystemPropertiesDetailRowModel> {
        return when (report.stage) {
            SystemPropertiesStage.LOADING -> placeholderRows(
                labels = listOf(
                    "Rules checked",
                    "Rules observed",
                    "Reflection hits",
                    "getprop hits",
                    "JVM hits",
                    "Native hits",
                    "Boot raw",
                    "RO serial checks",
                    "RO serial anomalies",
                    "Prop areas scanned",
                    "Prop area holes",
                    "Source mismatches",
                    "Cross-checks",
                    "Info props",
                ),
                status = DetectorStatus.info(InfoKind.SUPPORT),
                value = "Pending",
            )

            SystemPropertiesStage.FAILED -> placeholderRows(
                labels = listOf(
                    "Rules checked",
                    "Rules observed",
                    "Reflection hits",
                    "getprop hits",
                    "JVM hits",
                    "Native hits",
                    "Boot raw",
                    "RO serial checks",
                    "RO serial anomalies",
                    "Prop areas scanned",
                    "Prop area holes",
                    "Source mismatches",
                    "Cross-checks",
                    "Info props",
                ),
                status = DetectorStatus.info(InfoKind.ERROR),
                value = "Error",
            )

            SystemPropertiesStage.READY -> run {
                val crossCheckSignals = report.signals.filter(::isCrossCheckSignal)
                listOf(
                    SystemPropertiesDetailRowModel(
                        label = "Rules checked",
                        value = report.checkedRuleCount.toString(),
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                    SystemPropertiesDetailRowModel(
                        label = "Rules observed",
                        value = report.observedRuleCount.toString(),
                        status = if (report.observedRuleCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                            InfoKind.SUPPORT
                        ),
                    ),
                    SystemPropertiesDetailRowModel(
                        label = "Reflection hits",
                        value = report.reflectionHitCount.toString(),
                        status = if (report.reflectionHitCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                            InfoKind.SUPPORT
                        ),
                    ),
                    SystemPropertiesDetailRowModel(
                        label = "getprop hits",
                        value = report.getpropHitCount.toString(),
                        status = if (report.getpropHitCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                            InfoKind.SUPPORT
                        ),
                    ),
                    SystemPropertiesDetailRowModel(
                        label = "JVM hits",
                        value = report.jvmHitCount.toString(),
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                    SystemPropertiesDetailRowModel(
                        label = "Native hits",
                        value = report.nativeHitCount.toString(),
                        status = if (report.nativeHitCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                            InfoKind.SUPPORT
                        ),
                    ),
                    SystemPropertiesDetailRowModel(
                        label = "Boot raw",
                        value = report.bootParamHitCount.toString(),
                        status = if (report.bootParamHitCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                            InfoKind.SUPPORT
                        ),
                    ),
                    SystemPropertiesDetailRowModel(
                        label = "RO serial checks",
                        value = report.readOnlySerialCheckedCount.toString(),
                        status = if (report.readOnlySerialAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                            InfoKind.SUPPORT
                        ),
                    ),
                    SystemPropertiesDetailRowModel(
                        label = "RO serial anomalies",
                        value = report.readOnlySerialFindingCount.toString(),
                        status = when {
                            report.dangerSignals.any(::isReadOnlySerialSignal) -> DetectorStatus.danger()
                            report.readOnlySerialFindingCount > 0 -> DetectorStatus.warning()
                            report.readOnlySerialAvailable -> DetectorStatus.allClear()
                            else -> DetectorStatus.info(InfoKind.SUPPORT)
                        },
                    ),
                    SystemPropertiesDetailRowModel(
                        label = "Prop areas scanned",
                        value = report.propAreaContextCount.toString(),
                        status = if (report.propAreaAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                            InfoKind.SUPPORT
                        ),
                    ),
                    SystemPropertiesDetailRowModel(
                        label = "Prop area holes",
                        value = report.propAreaHoleCount.toString(),
                        status = when {
                            report.dangerSignals.any(::isPropAreaHoleSignal) -> DetectorStatus.danger()
                            report.propAreaHoleCount > 0 -> DetectorStatus.warning()
                            report.propAreaAvailable -> DetectorStatus.allClear()
                            else -> DetectorStatus.info(InfoKind.SUPPORT)
                        },
                    ),
                    SystemPropertiesDetailRowModel(
                        label = "Source mismatches",
                        value = report.sourceMismatchCount.toString(),
                        status = when {
                            report.dangerSignals.any { it.category == SystemPropertyCategory.SOURCE_CONSISTENCY } -> DetectorStatus.danger()
                            report.sourceMismatchCount > 0 -> DetectorStatus.warning()
                            else -> DetectorStatus.allClear()
                        },
                    ),
                    SystemPropertiesDetailRowModel(
                        label = "Cross-checks",
                        value = crossCheckSignals.size.toString(),
                        status = when {
                            crossCheckSignals.any { it.severity == SystemPropertySeverity.DANGER } -> DetectorStatus.danger()
                            crossCheckSignals.isNotEmpty() -> DetectorStatus.warning()
                            else -> DetectorStatus.allClear()
                        },
                    ),
                    SystemPropertiesDetailRowModel(
                        label = "Info props",
                        value = report.infoPropertyCount.toString(),
                        status = if (report.infoPropertyCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                            InfoKind.SUPPORT
                        ),
                    ),
                )
            }
        }
    }

    private fun signalRow(signal: SystemPropertySignal): SystemPropertiesDetailRowModel {
        val detailLines = buildList {
            add(signal.description)
            add("Source: ${sourceLabel(signal.source)}")
            add("Observed: ${signal.value}")
            signal.detail
                ?.takeIf { it.isNotBlank() && !it.equals(signal.description, ignoreCase = true) }
                ?.let { add(it) }
        }
        return SystemPropertiesDetailRowModel(
            label = signal.property,
            value = badgeValue(signal.value),
            status = signalStatus(signal),
            detail = detailLines.joinToString(separator = "\n"),
            detailMonospace = true,
        )
    }

    private fun infoRow(signal: SystemPropertySignal): SystemPropertiesDetailRowModel {
        return SystemPropertiesDetailRowModel(
            label = signal.description,
            value = badgeValue(signal.value),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            detail = buildString {
                append(signal.property)
                appendLine()
                append("Source: ")
                append(sourceLabel(signal.source))
                appendLine()
                append(signal.value)
            },
            detailMonospace = true,
        )
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus,
    ): List<SystemPropertiesHeaderFactModel> {
        return listOf(
            SystemPropertiesHeaderFactModel("Critical", value, status),
            SystemPropertiesHeaderFactModel("Review", value, status),
            SystemPropertiesHeaderFactModel("Boot", value, status),
            SystemPropertiesHeaderFactModel("Build", value, status),
        )
    }

    private fun placeholderRows(
        labels: List<String>,
        status: DetectorStatus,
        value: String,
        monospace: Boolean = false,
    ): List<SystemPropertiesDetailRowModel> {
        return labels.map { label ->
            SystemPropertiesDetailRowModel(
                label = label,
                value = value,
                status = status,
                detailMonospace = monospace,
            )
        }
    }

    private fun placeholderMethodRows(
        status: DetectorStatus,
        value: String,
    ): List<SystemPropertiesDetailRowModel> {
        return listOf(
            "Reflection API",
            "getprop snapshot",
            "JVM property fallback",
            "Native libc",
            "Raw boot params",
            "Build constants",
            "Source consistency",
            "Cross-check rules",
            "Read-only serials",
            "Prop area layout",
            "Property catalog",
        ).map { label ->
            SystemPropertiesDetailRowModel(
                label = label,
                value = value,
                status = status,
            )
        }
    }

    private fun categoryStatus(
        signals: List<SystemPropertySignal>,
    ): DetectorStatus {
        return when {
            signals.any { it.severity == SystemPropertySeverity.DANGER } -> DetectorStatus.danger()
            signals.any { it.severity == SystemPropertySeverity.WARNING } -> DetectorStatus.warning()
            signals.any { it.severity == SystemPropertySeverity.SAFE } -> DetectorStatus.allClear()
            else -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun countLabel(count: Int): String {
        return if (count > 0) count.toString() else "None"
    }

    private fun badgeValue(
        value: String,
    ): String {
        return if (value.length > MAX_BADGE_LENGTH) {
            value.take(MAX_BADGE_LENGTH - 1) + "…"
        } else {
            value
        }
    }

    private fun sourceLabel(
        source: SystemPropertySource,
    ): String {
        return when (source) {
            SystemPropertySource.REFLECTION -> "Reflection"
            SystemPropertySource.GETPROP -> "getprop"
            SystemPropertySource.JVM -> "System.getProperty"
            SystemPropertySource.BUILD -> "Build constant"
            SystemPropertySource.NATIVE_LIBC -> "Native libc"
            SystemPropertySource.CMDLINE -> "/proc/cmdline"
            SystemPropertySource.BOOTCONFIG -> "/proc/bootconfig"
        }
    }

    private fun signalStatus(
        signal: SystemPropertySignal,
    ): DetectorStatus {
        return when (signal.severity) {
            SystemPropertySeverity.SAFE -> DetectorStatus.allClear()
            SystemPropertySeverity.WARNING -> DetectorStatus.warning()
            SystemPropertySeverity.DANGER -> DetectorStatus.danger()
            SystemPropertySeverity.NEUTRAL -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun methodStatus(
        result: SystemPropertiesMethodResult,
    ): DetectorStatus {
        return when (result.outcome) {
            SystemPropertiesMethodOutcome.CLEAN -> DetectorStatus.allClear()
            SystemPropertiesMethodOutcome.WARNING -> DetectorStatus.warning()
            SystemPropertiesMethodOutcome.DANGER -> DetectorStatus.danger()
            SystemPropertiesMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun SystemPropertiesReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            SystemPropertiesStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            SystemPropertiesStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            SystemPropertiesStage.READY -> when {
                hasDangerSignals -> DetectorStatus.danger()
                hasWarningSignals -> DetectorStatus.warning()
                else -> DetectorStatus.allClear()
            }
        }
    }

    private fun isPropAreaHoleSignal(
        signal: SystemPropertySignal,
    ): Boolean {
        return signal.property.startsWith("prop_area hole:")
    }

    private fun isReadOnlySerialSignal(
        signal: SystemPropertySignal,
    ): Boolean {
        return signal.property.startsWith("ro serial anomaly:")
    }

    private fun isCrossCheckSignal(
        signal: SystemPropertySignal,
    ): Boolean {
        return signal.category == SystemPropertyCategory.PROPERTY_CONSISTENCY &&
                !isPropAreaHoleSignal(signal) &&
                !isReadOnlySerialSignal(signal)
    }

    companion object {
        private const val MAX_BADGE_LENGTH = 18
    }
}
