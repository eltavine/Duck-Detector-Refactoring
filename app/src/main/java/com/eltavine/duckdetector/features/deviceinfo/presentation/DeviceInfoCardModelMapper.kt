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

package com.eltavine.duckdetector.features.deviceinfo.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoReport
import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoStage
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoCardModel
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoHeaderFactModel
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoRowModel
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoSectionModel

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
            DeviceInfoStage.READY -> "Have a good day"
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
        fun valueOf(section: String, label: String): String {
            return report.sections.firstOrNull { it.title == section }
                ?.entries
                ?.firstOrNull { it.label == label }
                ?.value
                ?: when (report.stage) {
                    DeviceInfoStage.LOADING -> "Pending"
                    DeviceInfoStage.FAILED -> "Error"
                    DeviceInfoStage.READY -> "Unavailable"
                }
        }

        return listOf(
            DeviceInfoHeaderFactModel("Brand", valueOf("Identity", "Brand")),
            DeviceInfoHeaderFactModel("Model", valueOf("Identity", "Model")),
            DeviceInfoHeaderFactModel("Android", valueOf("Android", "Release")),
            DeviceInfoHeaderFactModel("SDK", valueOf("Android", "SDK")),
        )
    }

    private fun buildSections(report: DeviceInfoReport): List<DeviceInfoSectionModel> {
        return when (report.stage) {
            DeviceInfoStage.LOADING -> listOf(
                placeholderSection("Identity"),
                placeholderSection("Build"),
                placeholderSection("Android"),
                placeholderSection("Runtime"),
                placeholderSection("Context"),
            )

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

    private fun placeholderSection(title: String): DeviceInfoSectionModel {
        return DeviceInfoSectionModel(
            title = title,
            rows = listOf(
                DeviceInfoRowModel("Loading", "Pending"),
            ),
        )
    }
}
