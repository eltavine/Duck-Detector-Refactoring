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
     * Format device info into a compact summary suitable for clipboard copy.
     * Human-readable with section headers.
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
     * Format device info into an ultra-compact pipe-delimited blob for QR codes.
     *
     * Uses short keys, no section headers, no whitespace — optimised for
     * QR alphanumeric mode (~4.3 KB capacity). Skips "Unavailable" values.
     *
     * Format:  DD|t=yyMMddHHmm|av=1.0|br=Xiaomi|mo=...|fp=...
     */
    fun formatUltraCompact(model: DeviceInfoCardModel): String {
        val f = extractFactMap(model)
        val time = SimpleDateFormat("yyMMddHHmm", Locale.US).format(Date())

        return buildString {
            append("DD|")
            append("t=$time|")
            append("av=${BuildConfig.VERSION_NAME}|")

            // Identity
            f["Brand"]?.takeIf { it != "Unavailable" }?.let { append("br=$it|") }
            f["Manufacturer"]?.takeIf { it != "Unavailable" }?.let { append("mfr=$it|") }
            f["Model"]?.takeIf { it != "Unavailable" }?.let { append("mo=$it|") }
            f["Device"]?.takeIf { it != "Unavailable" }?.let { append("de=$it|") }
            f["Product"]?.takeIf { it != "Unavailable" }?.let { append("pr=$it|") }
            f["Board"]?.takeIf { it != "Unavailable" }?.let { append("bd=$it|") }

            // SOC
            f["SOC Manufacturer"]?.takeIf { it != "Unavailable" }?.let { append("sm=$it|") }
            f["SOC Model"]?.takeIf { it != "Unavailable" }?.let { append("sc=$it|") }
            f["CPU Hardware"]?.takeIf { it != "Unavailable" }?.let { append("ch=$it|") }
            f["Board Platform"]?.takeIf { it != "Unavailable" }?.let { append("bp=$it|") }
            f["Chip Name"]?.takeIf { it != "Unavailable" }?.let { append("cn=$it|") }
            f["CPU Cores"]?.takeIf { it != "Unavailable" && it != "0" }?.let { append("co=$it|") }
            f["CPU Architecture"]?.takeIf { it != "Unavailable" }?.let { append("ca=$it|") }

            // Build
            f["Hardware"]?.takeIf { it != "Unavailable" }?.let { append("hw=$it|") }
            f["Bootloader"]?.takeIf { it != "Unavailable" }?.let { append("bl=$it|") }
            f["Fingerprint"]?.takeIf { it != "Unavailable" }?.let { append("fp=$it|") }
            f["Build ID"]?.takeIf { it != "Unavailable" }?.let { append("bi=$it|") }
            f["Build type"]?.takeIf { it != "Unavailable" }?.let { append("bt=$it|") }
            f["Incremental"]?.takeIf { it != "Unavailable" }?.let { append("in=$it|") }

            // Android
            f["SDK"]?.takeIf { it != "Unavailable" }?.let { append("sk=$it|") }
            f["Release"]?.takeIf { it != "Unavailable" }?.let { append("re=$it|") }
            f["Security patch"]?.takeIf { it != "Unavailable" }?.let { append("sp=$it|") }
            f["Tags"]?.takeIf { it != "Unavailable" }?.let { append("tg=$it|") }
            f["Build user"]?.takeIf { it != "Unavailable" }?.let { append("bu=$it|") }
            f["Build host"]?.takeIf { it != "Unavailable" }?.let { append("bh=$it|") }

            // Runtime
            f["Primary ABI"]?.takeIf { it != "Unavailable" }?.let { append("ab=$it|") }
            f["Kernel"]?.takeIf { it != "Unavailable" }?.let { append("kn=$it|") }
            f["Locale"]?.takeIf { it != "Unavailable" }?.let { append("lo=$it|") }
            f["Time zone"]?.takeIf { it != "Unavailable" }?.let { append("tz=$it|") }

            if (endsWith('|')) setLength(length - 1)
        }
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
