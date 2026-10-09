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

package com.eltavine.duckdetector.features.systemproperties.presentation

import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodOutcome
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodResult
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesReport
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesStage
import com.eltavine.duckdetector.features.systemproperties.presentation.model.SystemPropertiesDetailRowModel

internal fun buildScanRows(report: SystemPropertiesReport): List<SystemPropertiesDetailRowModel> {
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
            val crossCheckSignals = report.crossCheckSignals
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
                        report.hasDangerPropAreaHole -> DetectorStatus.danger()
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

internal fun buildMethodRows(report: SystemPropertiesReport): List<SystemPropertiesDetailRowModel> {
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
        } + listOfNotNull(
            report.propertyAreaMtimes.takeIf { it.isNotEmpty() }?.let(::propertyAreaMtimeRow),
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
        "Prop area layout",
        "Property catalog",
        PROPERTY_AREA_MTIMES_LABEL,
    ).map { label ->
        SystemPropertiesDetailRowModel(
            label = label,
            value = value,
            status = status,
        )
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
