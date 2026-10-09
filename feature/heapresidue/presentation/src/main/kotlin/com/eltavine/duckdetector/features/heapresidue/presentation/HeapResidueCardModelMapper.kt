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
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueArgument
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueOutcome
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueReport
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueStage
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueProbeFailure
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueRetention
import com.eltavine.duckdetector.features.heapresidue.domain.toDetectorStatus
import com.eltavine.duckdetector.features.heapresidue.presentation.model.HeapResidueCardModel
import com.eltavine.duckdetector.features.heapresidue.presentation.model.HeapResidueDetailRowModel

class HeapResidueCardModelMapper {
    fun map(report: HeapResidueReport): HeapResidueCardModel = HeapResidueCardModel(
        title = "Zygote heap residue", subtitle = "Experimental ART snapshot · low confidence",
        status = report.toDetectorStatus(), verdict = verdict(report),
        summary = when {
            report.stage == HeapResidueStage.LOADING -> "Capturing a fresh isolated-process heap."
            report.outcome == HeapResidueOutcome.UNSUPPORTED -> "Only the Android 16 ART baseline is audited. Other versions are unsupported."
            report.outcome == HeapResidueOutcome.UNAVAILABLE -> "The isolated heap probe was unavailable. No absence conclusion is possible."
            report.outcome == HeapResidueOutcome.INCONCLUSIVE -> "The snapshot could not establish usable startup argument evidence. Coverage is unknown."
            report.outcome == HeapResidueOutcome.OBSERVED -> "Exact target names occurred in startup argument strings. Origin and launch time are unverified; this does not prove current installation or compromise."
            else -> "No target trace was observed in this snapshot. GC, USAP, native fork paths and other zygote instances can hide traces; startup history is incomplete."
        },
        signalRows = report.signals.map { signal ->
            HeapResidueDetailRowModel(signal.packageName, "Argument trace", DetectorStatus.warning(),
                signal.arguments.joinToString { argument -> when (argument) {
                    HeapResidueArgument.PACKAGE_NAME -> "package-name"
                    HeapResidueArgument.NICE_NAME -> "nice-name"
                    HeapResidueArgument.APP_DATA_DIR -> "app-data-dir"
                } } + ". These are correlated strings from one snapshot, not independent evidence.")
        },
        scanRows = scanRows(report),
    )

    private fun verdict(report: HeapResidueReport): String = when {
        report.stage == HeapResidueStage.LOADING -> "Scanning"
        else -> when (report.outcome) {
            HeapResidueOutcome.NOT_EVALUATED -> "Not evaluated"
            HeapResidueOutcome.UNSUPPORTED -> "Unsupported"
            HeapResidueOutcome.UNAVAILABLE -> "Probe unavailable"
            HeapResidueOutcome.INCONCLUSIVE -> "Inconclusive"
            HeapResidueOutcome.NOT_OBSERVED -> "No target trace observed"
            HeapResidueOutcome.OBSERVED -> "Target argument traces observed"
        }
    }

    private fun scanRows(report: HeapResidueReport): List<HeapResidueDetailRowModel> {
        if (report.stage == HeapResidueStage.LOADING) return emptyList()
        val status = DetectorStatus.info(InfoKind.SUPPORT)
        return buildList {
            add(HeapResidueDetailRowModel("Coverage", "Unknown", status,
                "Same-zygote snapshot only; no complete history since boot. Package names can be spoofed. OEM and GC timing require device validation."))
            add(HeapResidueDetailRowModel("Dump bytes parsed", report.bytesRead.toString(), status))
            add(HeapResidueDetailRowModel("Startup argument strings", report.candidateCount.toString(), status,
                "Excludes this app's own arguments, which every fresh child carries."))
            report.captureAgeMillis?.let { add(HeapResidueDetailRowModel("Age at dump entry", "$it ms", status,
                "Measured from Process.getStartUptimeMillis, not an exact fork-to-snapshot interval. Hidden API setup follows this measurement.")) }
            report.dumpDurationMillis?.let { add(HeapResidueDetailRowModel("Dump call duration", "$it ms", status)) }
            report.gcCountBefore?.let { add(HeapResidueDetailRowModel("GC count before dump", it.toString(), status,
                "Diagnostic counter; neither collector generation nor retained historical coverage is established.")) }
            add(HeapResidueDetailRowModel("Local debug retention", when (report.retention) {
                HeapResidueRetention.UNKNOWN -> "Not reported"
                HeapResidueRetention.DISABLED -> "Disabled"
                HeapResidueRetention.SAVED -> "Saved locally"
                HeapResidueRetention.TOO_LARGE -> "Size limit exceeded"
                HeapResidueRetention.FAILED -> "Retention failed"
            }, status, "Debuggable builds only; at most two dumps and 64 MiB in no-backup storage. Raw heaps are never included in reports."))
            report.probeFailure?.let { failure -> add(HeapResidueDetailRowModel("Unavailable stage", when (failure) {
                HeapResidueProbeFailure.BINDING -> "Service binding"
                HeapResidueProbeFailure.HIDDEN_API -> "Hidden dump API"
                HeapResidueProbeFailure.DUMP -> "ART heap dump"
                HeapResidueProbeFailure.TIMEOUT -> "Capture deadline"
                HeapResidueProbeFailure.MALFORMED_HPROF -> "HPROF structure or byte limit"
                HeapResidueProbeFailure.STREAM -> "Heap stream"
            }, DetectorStatus.info(InfoKind.ERROR))) }
            report.errorMessage?.let { add(HeapResidueDetailRowModel("Probe detail", it, DetectorStatus.info(InfoKind.ERROR))) }
        }
    }
}
