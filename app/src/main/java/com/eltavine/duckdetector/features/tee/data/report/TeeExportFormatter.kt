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

package com.eltavine.duckdetector.features.tee.data.report

import com.eltavine.duckdetector.features.tee.domain.TeeReport

class TeeExportFormatter {

    fun format(report: TeeReport): String {
        return buildString {
            appendLine(report.headline)
            appendLine(report.summary)
            appendLine()
            appendLine("Verdict: ${report.verdict}")
            appendLine("Tier: ${report.tier}")
            appendLine("Trust root: ${report.trustRoot}")
            appendLine("Trust summary: ${report.trustSummary}")
            appendLine("Tamper score: ${report.tamperScore}")
            appendLine("Evidence count: ${report.evidenceCount}")
            appendLine("Network: ${report.networkState.summary}")
            appendLine("Soter: ${report.soterState.summary}")
            appendLine()
            report.sections.forEach { section ->
                appendLine(section.title)
                section.items.forEach { item ->
                    append("- ")
                    append(item.title)
                    append(": ")
                    appendLine(item.body)
                }
                appendLine()
            }
            if (report.certificates.isNotEmpty()) {
                appendLine("Certificates")
                report.certificates.forEach { cert ->
                    append("- ")
                    append(cert.slotLabel)
                    append(": ")
                    append(cert.subject)
                    append(" -> ")
                    appendLine(cert.issuer)
                }
            }
        }.trim()
    }
}
