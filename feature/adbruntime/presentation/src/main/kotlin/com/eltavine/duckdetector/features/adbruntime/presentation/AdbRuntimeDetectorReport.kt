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

package com.eltavine.duckdetector.features.adbruntime.presentation

import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.core.report.ReportBlock
import com.eltavine.duckdetector.core.report.ReportRow
import com.eltavine.duckdetector.features.adbruntime.presentation.model.AdbRuntimeCardModel
import com.eltavine.duckdetector.features.adbruntime.presentation.model.AdbRuntimeDetailRowModel

fun AdbRuntimeCardModel.toDetectorReport(): DetectorReport = DetectorReport(
    title = title,
    verdict = verdict,
    severity = status.severity,
    quickFacts = emptyList(),
    blocks = listOf(
        ReportBlock.Rows("Inconsistencies", signalRows.toReportRows()),
        ReportBlock.Rows("Sources", scanRows.toReportRows()),
    ),
)

private fun List<AdbRuntimeDetailRowModel>.toReportRows(): List<ReportRow> =
    map { ReportRow(it.label, it.value, it.detail) }
