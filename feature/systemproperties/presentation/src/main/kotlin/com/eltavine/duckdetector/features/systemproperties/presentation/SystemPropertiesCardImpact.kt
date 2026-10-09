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
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySignal
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesReport
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesStage
import com.eltavine.duckdetector.features.systemproperties.domain.hasReducedCoverage
import com.eltavine.duckdetector.features.systemproperties.presentation.model.SystemPropertiesImpactItemModel

internal fun buildImpactItems(report: SystemPropertiesReport): List<SystemPropertiesImpactItemModel> {
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
            val crossCheckSignals = report.crossCheckSignals
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
            if (report.propAreaHoleCount > 0) {
                add(
                    SystemPropertiesImpactItemModel(
                        text = "Raw /dev/__properties__ hole residue means the property storage layout no longer matches a normal append-only allocation pattern.",
                        status = if (report.hasDangerPropAreaHole) {
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
                    if (report.hasReducedCoverage()) {
                        SystemPropertiesImpactItemModel(
                            text = "Observed properties matched conservative expectations, but raw property-area layout coverage was unavailable.",
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                        )
                    } else {
                        SystemPropertiesImpactItemModel(
                            text = "Observed key properties matched conservative production expectations across multiple read paths.",
                            status = DetectorStatus.allClear(),
                        )
                    },
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

internal val SystemPropertiesReport.crossCheckSignals: List<SystemPropertySignal>
    get() = propertySignals.filter { it.category == SystemPropertyCategory.PROPERTY_CONSISTENCY }

internal val SystemPropertiesReport.hasDangerPropAreaHole: Boolean
    get() = propAreaSignals.any { it.severity == SystemPropertySeverity.DANGER }
