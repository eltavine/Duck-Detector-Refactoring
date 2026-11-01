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

package com.eltavine.duckdetector.features.dangerousapps.presentation

import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.core.report.ReportBlock
import com.eltavine.duckdetector.core.report.ReportFact
import com.eltavine.duckdetector.core.report.ReportRow
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsCardModel

private const val CATALOG_LINE_WIDTH = 95

fun DangerousAppsCardModel.toDetectorReport(): DetectorReport = DetectorReport(
    title = title,
    verdict = verdict,
    severity = status.severity,
    quickFacts = headerFacts.map { ReportFact(it.label, it.value) },
    blocks = buildList {
        hmaAlert?.let { alert ->
            add(
                ReportBlock.Verbatim(
                    title = "HMA Alert: ${alert.title}",
                    lines = buildList {
                        add("    Summary: ${alert.summary}")
                        if (alert.hiddenPackages.isNotEmpty()) {
                            add("    Hidden Packages:")
                            alert.hiddenPackages.forEach { pkg ->
                                add("      • ${pkg.appName} (${pkg.packageName}) [methods: ${pkg.methods.joinToString()}]")
                            }
                        }
                    },
                ),
            )
        }
        if (packageItems.isNotEmpty()) {
            add(
                ReportBlock.Verbatim(
                    title = "Detected Packages",
                    lines = packageItems.map { pkg ->
                        "    • ${pkg.appName} (${pkg.packageName}) [methods: ${pkg.methods.joinToString()}]"
                    },
                ),
            )
        }
        packageHistory?.let { history ->
            add(
                ReportBlock.Verbatim(
                    title = "Package Changes Since Boot",
                    lines = listOf("    ${history.summary}") + history.packages.map { pkg ->
                        "    • ${pkg.appName} (${pkg.packageName}) [${pkg.category}; current installation unconfirmed]"
                    },
                ),
            )
        }
        add(ReportBlock.Rows("Impact", impactRows.map { ReportRow(it.label, it.value, it.detail) }))
        add(ReportBlock.Rows("Detection methods", methodRows.map { ReportRow(it.label, it.value, it.detail) }))
        add(ReportBlock.Rows("Scan summary", context.map { ReportRow(it.label, it.value, it.detail) }))
        if (targetApps.isNotEmpty()) {
            val byCategory = targetApps.groupBy { it.category }
            add(
                ReportBlock.Verbatim(
                    title = "Monitored Package Catalog (${targetApps.size} targets across ${byCategory.size} categories)",
                    lines = buildList {
                        byCategory.forEach { (category, apps) ->
                            add("    • $category (${apps.size}):")
                            addAll(wrapCatalogItems("        ", apps.map { "${it.appName} (${it.packageName})" }))
                        }
                    },
                ),
            )
        }
    },
)

/** Packs items onto lines of at most [CATALOG_LINE_WIDTH] columns without ever splitting an item. */
private fun wrapCatalogItems(indent: String, items: List<String>): List<String> {
    val lines = mutableListOf<String>()
    var currentLine = StringBuilder(indent)
    items.forEachIndexed { index, item ->
        val suffix = if (index < items.lastIndex) ", " else ""
        if (currentLine.length + item.length + suffix.length > CATALOG_LINE_WIDTH && currentLine.trim().isNotEmpty()) {
            lines += currentLine.toString()
            currentLine = StringBuilder(indent).append(item).append(suffix)
        } else {
            currentLine.append(item).append(suffix)
        }
    }
    if (currentLine.trim().isNotEmpty()) {
        lines += currentLine.toString()
    }
    return lines
}
