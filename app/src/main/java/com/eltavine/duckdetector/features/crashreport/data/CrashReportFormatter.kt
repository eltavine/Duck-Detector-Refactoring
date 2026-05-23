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

package com.eltavine.duckdetector.features.crashreport.data

import com.eltavine.duckdetector.features.crashreport.domain.CrashReport
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Formats [CrashReport] into a human-readable plain-text report.
 */
object CrashReportFormatter {

    fun format(report: CrashReport): String = buildString {
        appendLine("========================================")
        appendLine("  Duck Detector — CRASH REPORT")
        appendLine("========================================")
        appendLine()
        appendLine("Crash Time (UTC) : ${report.crashTimeIso}")
        appendLine(
            "Crash Time (local): ${
                SimpleDateFormat("yyyy-MM-dd HH:mm:ss (z)", Locale.US).format(
                    Date(report.crashTimeUtcMillis),
                )
            }",
        )
        appendLine()

        // --- App info ---
        appendLine("----- APP INFO -----")
        appendLine("Version    : ${report.appVersionName} (${report.appVersionCode})")
        appendLine("Build Hash : ${report.appBuildHash}")
        appendLine("Build Time : ${report.appBuildTimeUtc} (UTC)")
        appendLine()

        // --- Process context ---
        appendLine("----- PROCESS CONTEXT -----")
        appendLine("Thread  : ${report.threadName}")
        appendLine("Process : ${report.processName}")
        appendLine("PID     : ${report.pid}")
        appendLine()

        // --- Device info ---
        report.deviceSections.forEach { section ->
            appendLine("----- ${section.title.uppercase(Locale.US)} -----")
            section.entries.forEach { entry ->
                appendLine("  ${entry.label}: ${entry.value}")
            }
            appendLine()
        }

        // --- Exception ---
        appendLine("----- EXCEPTION -----")
        appendLine("Class   : ${report.exceptionClassName}")
        appendLine("Message : ${report.exceptionMessage}")
        appendLine()

        // --- Cause chain ---
        if (report.causeChain.isNotEmpty()) {
            appendLine("----- CAUSE CHAIN -----")
            report.causeChain.forEachIndexed { index, cause ->
                appendLine("  [$index] $cause")
            }
            appendLine()
        }

        // --- Stack trace ---
        appendLine("----- STACK TRACE -----")
        appendLine(report.stackTrace)
        appendLine()

        appendLine("========================================")
        appendLine("  End of crash report")
        appendLine("========================================")
    }

    private fun StringBuilder.appendLine(value: String = "") {
        append(value)
        append('\n')
    }
}
