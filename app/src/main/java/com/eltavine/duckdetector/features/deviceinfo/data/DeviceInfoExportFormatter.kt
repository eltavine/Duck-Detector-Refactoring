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

package com.eltavine.duckdetector.features.deviceinfo.data

import com.eltavine.duckdetector.BuildConfig
import com.eltavine.duckdetector.core.ui.presentation.formatBuildTimeUtc
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoCardModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object DeviceInfoExportFormatter {

    /**
     * Format device info into a compact single-line summary suitable for QR code encoding.
     * QR codes have limited capacity, so this format is concise.
     */
    fun formatCompact(model: DeviceInfoCardModel): String = buildString {
        val facts = extractFactMap(model)

        append("=== DuckDetector Device Info ===\n")
        append("App: ${BuildConfig.VERSION_NAME}(${BuildConfig.VERSION_CODE})\n")
        append("Time: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}\n")
        append("\n")

        // Identity
        append("[Identity]\n")
        append("Brand: ${facts["Brand"]}\n")
        append("Manufacturer: ${facts["Manufacturer"]}\n")
        append("Model: ${facts["Model"]}\n")
        append("Device: ${facts["Device"]}\n")
        append("Product: ${facts["Product"]}\n")
        append("Board: ${facts["Board"]}\n")
        append("\n")

        // SOC
        append("[SOC]\n")
        append("SOC Mfr: ${facts["SOC Manufacturer"]}\n")
        append("SOC Model: ${facts["SOC Model"]}\n")
        append("CPU HW: ${facts["CPU Hardware"]}\n")
        append("Platform: ${facts["Board Platform"]}\n")
        append("Chip: ${facts["Chip Name"]}\n")
        append("Cores: ${facts["CPU Cores"]}\n")
        append("Arch: ${facts["CPU Architecture"]}\n")
        append("\n")

        // Build
        append("[Build]\n")
        append("HW: ${facts["Hardware"]}\n")
        append("Bootloader: ${facts["Bootloader"]}\n")
        append("Fingerprint: ${facts["Fingerprint"]}\n")
        append("ID: ${facts["Build ID"]}\n")
        append("Type: ${facts["Build type"]}\n")
        append("Incremental: ${facts["Incremental"]}\n")
        append("\n")

        // Android
        append("[Android]\n")
        append("SDK: ${facts["SDK"]}\n")
        append("Release: ${facts["Release"]}\n")
        append("Security: ${facts["Security patch"]}\n")
        append("Tags: ${facts["Tags"]}\n")
        append("User: ${facts["Build user"]}\n")
        append("Host: ${facts["Build host"]}\n")
        append("\n")

        // Runtime
        append("[Runtime]\n")
        append("ABI: ${facts["Primary ABI"]}\n")
        append("Kernel: ${facts["Kernel"]}\n")
        append("Locale: ${facts["Locale"]}\n")
        append("TZ: ${facts["Time zone"]}\n")

        append("=== End ===\n")
    }

    /**
     * Format device info into a detailed multi-line text report suitable for TXT file export.
     */
    fun formatFull(model: DeviceInfoCardModel): String = buildString {
        appendLine("========================================")
        appendLine("  Duck Detector — Device Info Report")
        appendLine("========================================")
        appendLine()
        appendLine("App Version : ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
        appendLine("Build Hash  : ${BuildConfig.BUILD_HASH}")
        appendLine("Build Time  : ${formatBuildTimeUtc(BuildConfig.BUILD_TIME_UTC)} (UTC)")
        appendLine("Report Time : ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss (z)", Locale.US).format(Date())}")
        appendLine()

        appendLine("----- HEADER FACTS -----")
        model.headerFacts.forEach { fact ->
            appendLine("  ${fact.label}: ${fact.value}")
        }
        appendLine()

        model.sections.forEach { section ->
            appendLine("----- ${section.title.uppercase(Locale.US)} -----")
            section.rows.forEach { row ->
                appendLine("  ${row.label}: ${row.value}")
            }
            appendLine()
        }

        appendLine("========================================")
        appendLine("  End of device info report")
        appendLine("========================================")
    }

    private fun extractFactMap(model: DeviceInfoCardModel): Map<String, String> {
        val map = mutableMapOf<String, String>()

        model.headerFacts.forEach { fact ->
            map[fact.label] = fact.value
        }

        model.sections.forEach { section ->
            section.rows.forEach { row ->
                map[row.label] = row.value
            }
        }

        return map
    }

    private fun StringBuilder.appendLine(value: String = "") {
        append(value)
        append('\n')
    }
}
