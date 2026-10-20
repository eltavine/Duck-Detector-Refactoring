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

package com.eltavine.duckdetector.features.nativeroot.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.nativeroot.domain.InitRcTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.InitRcTimingObservation
import com.eltavine.duckdetector.features.nativeroot.domain.InitRcTimingVerdict
import com.eltavine.duckdetector.features.nativeroot.presentation.model.NativeRootDetailRowModel
import java.util.Locale

internal fun initRcTimingRow(observation: InitRcTimingObservation): NativeRootDetailRowModel {
    val analysis = observation.analysis
    val value = when (observation.collection) {
        InitRcTimingCollection.NOT_RUN -> "Not run"
        InitRcTimingCollection.UNSUPPORTED_ABI -> "Unsupported ABI"
        InitRcTimingCollection.COLLECTED -> when (analysis.verdict) {
            InitRcTimingVerdict.REPEATABLE_INTERACTION -> "Repeatable interaction (experimental)"
            InitRcTimingVerdict.NO_REPEATABLE_INTERACTION -> "No repeatable interaction"
            else -> "Inconclusive"
        }
        InitRcTimingCollection.TIMED_OUT -> "Timed out"
        InitRcTimingCollection.CLEANUP_FAILED -> "Cleanup failed"
        else -> "Unavailable"
    }
    return NativeRootDetailRowModel(
        label = "init.rc hook timing",
        value = value,
        status = DetectorStatus.info(InfoKind.SUPPORT),
        detail = buildString {
            appendLine("Experimental supporting evidence; does not identify or exclude KernelSU.")
            appendLine("Tests the interaction of comm init and a private init.rc filename using raw arm64 fstat.")
            appendLine("The reviewed pre-3924 hook must still be installed; successful boot removes it and late-load skips it.")
            appendLine("Same-metadata control, balanced order and single-CPU checks reduce confounding but do not establish causality.")
            appendLine("Repeatability rules are provisional; physical-device detection accuracy is uncalibrated.")
            appendLine("Collection: ${observation.collection}; errno=${observation.errorNumber}; CPU=${observation.cpu}")
            appendLine("Cleanup: ${observation.cleanupCompleted}; cleanup errno=${observation.cleanupErrorNumber}")
            appendLine("Complete rounds: ${observation.rounds.size}/32; calls/batch=${observation.iterations}")
            if (analysis.orderMediansNanos.isNotEmpty()) {
                appendLine("Median interaction: ${analysis.medianContrastNanos.ns()} ns/call; MAD: ${analysis.madNanos.ns()}")
                appendLine("Positive rounds: ${analysis.positiveRounds}/32")
                appendLine("Order medians (ns/call): ${analysis.orderMediansNanos.joinToString { it.ns() }}")
            }
            if (observation.failureDetail.isNotBlank()) appendLine(observation.failureDetail)
            if (observation.rounds.isNotEmpty()) {
                appendLine("Raw batch ns: round / duck-data / duck-init / init-data / init-init")
                observation.rounds.forEachIndexed { index, round ->
                    appendLine("$index\t${round.durations.joinToString("\t")}")
                }
            }
        }.trimEnd(),
        detailMonospace = true,
    )
}

private fun Double.ns(): String = String.format(Locale.ROOT, "%.2f", this)
