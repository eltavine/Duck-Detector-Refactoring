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

package com.eltavine.duckdetector.features.zygisk.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskMethod
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskReport
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskSignal
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskSignalGroup
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskSignalSeverity
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskStage
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskDetailRowModel
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskRowIcon

internal fun buildSignalRows(
    report: ZygiskReport,
): List<ZygiskDetailRowModel> {
    return when (report.stage) {
        ZygiskStage.LOADING -> placeholderSignalRows(DetectorStatus.info(InfoKind.SUPPORT), "Pending")

        ZygiskStage.FAILED -> placeholderSignalRows(DetectorStatus.info(InfoKind.ERROR), "Error")

        ZygiskStage.READY -> {
            if (report.signals.isEmpty()) {
                listOf(
                    ZygiskDetailRowModel(
                        label = "Signals",
                        value = if (report.fullyClean) "Clean" else "Unavailable",
                        status = if (report.fullyClean) {
                            DetectorStatus.allClear()
                        } else {
                            DetectorStatus.info(InfoKind.SUPPORT)
                        },
                        detail = if (report.fullyClean) {
                            "No positive runtime signal surfaced in the current process."
                        } else {
                            "No positive signal surfaced, but a major scan path was unavailable so the result is support-only."
                        },
                    ),
                )
            } else {
                report.signals.map(::signalRow)
            }
        }
    }
}

private fun signalRow(
    signal: ZygiskSignal,
): ZygiskDetailRowModel {
    return ZygiskDetailRowModel(
        label = signal.label,
        value = signal.value,
        status = when (signal.severity) {
            ZygiskSignalSeverity.DANGER -> DetectorStatus.danger()
            ZygiskSignalSeverity.WARNING -> DetectorStatus.warning()
        },
        detail = signal.detail,
        detailMonospace = signal.detailMonospace,
        icon = signal.group.rowIcon(),
    )
}

private fun placeholderSignalRows(
    status: DetectorStatus,
    value: String,
): List<ZygiskDetailRowModel> {
    return ZygiskSignalGroup.entries.map { group ->
        ZygiskDetailRowModel(label = group.placeholderLabel(), value = value, status = status, icon = group.rowIcon())
    }
}

private fun ZygiskSignalGroup.placeholderLabel(): String = when (this) {
    ZygiskSignalGroup.CROSS_PROCESS -> "Cross-process"
    ZygiskSignalGroup.RUNTIME -> "Runtime"
    ZygiskSignalGroup.LINKER -> "Linker"
    ZygiskSignalGroup.MAPS -> "Maps"
    ZygiskSignalGroup.HEAP -> "Heap"
    ZygiskSignalGroup.THREADS -> "Threads"
    ZygiskSignalGroup.FD -> "FDs"
}

internal fun ZygiskSignalGroup.rowIcon(): ZygiskRowIcon? = when (this) {
    ZygiskSignalGroup.CROSS_PROCESS -> ZygiskRowIcon.CROSS_PROCESS
    ZygiskSignalGroup.LINKER -> ZygiskRowIcon.LINKER
    ZygiskSignalGroup.MAPS,
    ZygiskSignalGroup.HEAP -> ZygiskRowIcon.MEMORY
    ZygiskSignalGroup.RUNTIME,
    ZygiskSignalGroup.THREADS,
    ZygiskSignalGroup.FD -> null
}

internal fun ZygiskMethod.rowIcon(): ZygiskRowIcon? = when (this) {
    ZygiskMethod.CROSS_PROCESS_FD_TRAP -> ZygiskRowIcon.CROSS_PROCESS
    ZygiskMethod.LINKER_AND_NAMESPACE -> ZygiskRowIcon.LINKER
    ZygiskMethod.MAPS_AND_SMAPS,
    ZygiskMethod.SOLIST_ATEXIT_HEAP -> ZygiskRowIcon.MEMORY
    ZygiskMethod.ATEXIT_HANDLERS -> ZygiskRowIcon.LINKER
    ZygiskMethod.NATIVE_SNAPSHOT,
    ZygiskMethod.THREADS_AND_FDS -> null
}
