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

package com.eltavine.duckdetector.features.heapresidue.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueOutcome
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueReport
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueStage
import com.eltavine.duckdetector.features.heapresidue.domain.toDetectorStatus
import com.eltavine.duckdetector.features.heapresidue.presentation.model.HeapResidueDetailRowModel

internal fun heapResidueHeaderFacts(report: HeapResidueReport): List<HeapResidueDetailRowModel> {
    val support = DetectorStatus.info(InfoKind.SUPPORT)
    val collected = report.stage == HeapResidueStage.READY && report.outcome in setOf(
        HeapResidueOutcome.OBSERVED, HeapResidueOutcome.NOT_OBSERVED, HeapResidueOutcome.INCONCLUSIVE,
    )
    val pending = if (report.stage == HeapResidueStage.LOADING) "Pending" else "Unavailable"
    val measurementStatus = if (report.stage == HeapResidueStage.FAILED) report.toDetectorStatus() else support
    return listOf(
        HeapResidueDetailRowModel("Traces", when {
            report.stage != HeapResidueStage.READY -> pending
            report.outcome == HeapResidueOutcome.INCONCLUSIVE -> "Inconclusive"
            collected -> report.signals.size.toString()
            else -> pending
        }, report.toDetectorStatus()),
        HeapResidueDetailRowModel("Arguments", if (collected) report.candidateCount.toString() else pending, measurementStatus),
        HeapResidueDetailRowModel("Snapshot", if (collected) "${report.bytesRead} bytes" else pending, measurementStatus),
        HeapResidueDetailRowModel("Coverage", "Unknown", support),
    )
}

internal fun heapResidueImpactRows(report: HeapResidueReport): List<HeapResidueDetailRowModel> = listOf(
    HeapResidueDetailRowModel("Interpretation", if (report.signals.isNotEmpty()) "Low-confidence argument residue" else "Historical coverage unknown",
        report.toDetectorStatus(), "Strings from one snapshot are correlated evidence. Names can be spoofed; origin and launch time are unverified. Neither a match nor a negative snapshot establishes current installation or compromise."),
)

internal fun heapResidueMethodRows(report: HeapResidueReport): List<HeapResidueDetailRowModel> {
    val status = report.toDetectorStatus()
    val capture = when {
        report.stage == HeapResidueStage.LOADING -> "Pending"
        report.stage == HeapResidueStage.FAILED -> "Unavailable"
        report.outcome == HeapResidueOutcome.UNSUPPORTED -> "Unsupported"
        report.outcome == HeapResidueOutcome.UNAVAILABLE -> "Unavailable"
        report.outcome == HeapResidueOutcome.NOT_EVALUATED -> "Not evaluated"
        else -> "Snapshot collected"
    }
    val parsed = report.stage == HeapResidueStage.READY && report.outcome in setOf(
        HeapResidueOutcome.OBSERVED, HeapResidueOutcome.NOT_OBSERVED, HeapResidueOutcome.INCONCLUSIVE,
    )
    return listOf(
        HeapResidueDetailRowModel("Isolated ART heap capture", capture, if (parsed) DetectorStatus.info(InfoKind.SUPPORT) else status,
            "A fresh isolated process streams a bounded HPROF snapshot. Binding, dump, timeout and parser failures remain distinguishable in the scan summary."),
        HeapResidueDetailRowModel("Startup argument matching", when {
            report.stage != HeapResidueStage.READY -> capture
            report.outcome == HeapResidueOutcome.INCONCLUSIVE -> "Inconclusive"
            parsed -> "${report.signals.size} target trace(s)"
            else -> capture
        }, status,
            "Exact catalog names are matched in package-name, nice-name and app-data-dir arguments. This app's own arguments are excluded; a completed negative snapshot is informational."),
    )
}
