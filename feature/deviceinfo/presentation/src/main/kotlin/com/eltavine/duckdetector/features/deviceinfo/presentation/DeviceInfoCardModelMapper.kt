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

package com.eltavine.duckdetector.features.deviceinfo.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoKey
import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoReport
import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoSectionKind
import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoStage
import com.eltavine.duckdetector.features.deviceinfo.presentation.model.DeviceInfoCardModel
import com.eltavine.duckdetector.features.deviceinfo.presentation.model.DeviceInfoHeaderFact
import com.eltavine.duckdetector.features.deviceinfo.presentation.model.DeviceInfoHeaderFactModel
import com.eltavine.duckdetector.features.deviceinfo.presentation.model.DeviceInfoRowModel
import com.eltavine.duckdetector.features.deviceinfo.presentation.model.DeviceInfoSectionModel

class DeviceInfoCardModelMapper {

    fun map(report: DeviceInfoReport): DeviceInfoCardModel {
        return DeviceInfoCardModel(
            title = "Device Info",
            subtitle = buildSubtitle(report),
            status = if (report.stage == DeviceInfoStage.FAILED) {
                DetectorStatus.info(InfoKind.ERROR)
            } else {
                DetectorStatus.info(InfoKind.SUPPORT)
            },
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            sections = buildSections(report),
        )
    }

    private fun buildSubtitle(report: DeviceInfoReport): String {
        return when (report.stage) {
            DeviceInfoStage.LOADING -> "identity + build + android + runtime + display"
            DeviceInfoStage.FAILED -> "local device profile unavailable"
            DeviceInfoStage.READY -> "${report.totalCount} local device facts"
        }
    }

    private fun buildVerdict(report: DeviceInfoReport): String {
        return when (report.stage) {
            DeviceInfoStage.LOADING -> "Collecting local device profile"
            DeviceInfoStage.FAILED -> "Device profile unavailable"
            DeviceInfoStage.READY -> "Device profile collected"
        }
    }

    private fun buildSummary(report: DeviceInfoReport): String {
        return when (report.stage) {
            DeviceInfoStage.LOADING -> "This card is purely contextual and does not affect detector severity or ranking."
            DeviceInfoStage.FAILED -> report.errorMessage ?: "Device info collection failed."
            DeviceInfoStage.READY -> "This card is informational only. It gives you a fixed local profile snapshot to read alongside the detector cards above."
        }
    }

    private fun buildHeaderFacts(report: DeviceInfoReport): List<DeviceInfoHeaderFactModel> {
        fun valueOf(key: DeviceInfoKey): String {
            return report.sections.asSequence()
                .flatMap { it.entries }
                .firstOrNull { it.key == key }
                ?.value
                ?: when (report.stage) {
                    DeviceInfoStage.LOADING -> "Pending"
                    DeviceInfoStage.FAILED -> "Error"
                    DeviceInfoStage.READY -> "Unavailable"
                }
        }

        return listOf(
            DeviceInfoHeaderFactModel(DeviceInfoHeaderFact.BRAND, valueOf(DeviceInfoKey.BRAND)),
            DeviceInfoHeaderFactModel(DeviceInfoHeaderFact.MODEL, valueOf(DeviceInfoKey.MODEL)),
            DeviceInfoHeaderFactModel(DeviceInfoHeaderFact.ANDROID, valueOf(DeviceInfoKey.ANDROID_RELEASE)),
            DeviceInfoHeaderFactModel(DeviceInfoHeaderFact.SDK, valueOf(DeviceInfoKey.SDK)),
        )
    }

    private fun buildSections(report: DeviceInfoReport): List<DeviceInfoSectionModel> {
        return when (report.stage) {
            DeviceInfoStage.LOADING -> DeviceInfoSectionKind.entries.map(::placeholderSection)

            DeviceInfoStage.FAILED -> listOf(
                DeviceInfoSectionModel(
                    title = "Unavailable",
                    rows = listOf(
                        DeviceInfoRowModel(
                            label = "Reason",
                            value = report.errorMessage ?: "Unknown error",
                        ),
                    ),
                ),
            )

            DeviceInfoStage.READY -> report.sections.map { section ->
                DeviceInfoSectionModel(
                    title = section.title,
                    kind = section.kind,
                    rows = section.entries.map { entry ->
                        DeviceInfoRowModel(
                            label = entry.label,
                            value = entry.value,
                            detailMonospace = entry.detailMonospace,
                        )
                    },
                )
            }
        }
    }

    private fun placeholderSection(kind: DeviceInfoSectionKind): DeviceInfoSectionModel {
        return DeviceInfoSectionModel(
            title = kind.title,
            kind = kind,
            rows = listOf(
                DeviceInfoRowModel("Loading", "Pending"),
            ),
        )
    }
}
