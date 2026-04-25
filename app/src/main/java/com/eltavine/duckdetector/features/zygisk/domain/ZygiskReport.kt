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

package com.eltavine.duckdetector.features.zygisk.domain

enum class ZygiskStage {
    LOADING,
    READY,
    FAILED,
}

enum class ZygiskSignalGroup {
    CROSS_PROCESS,
    RUNTIME,
    LINKER,
    MAPS,
    HEAP,
    THREADS,
    FD,
}

enum class ZygiskSignalSeverity(
    val label: String,
) {
    DANGER("Danger"),
    WARNING("Review"),
}

enum class ZygiskMethodOutcome {
    CLEAN,
    WARNING,
    DETECTED,
    SUPPORT,
}

data class ZygiskSignal(
    val id: String,
    val label: String,
    val value: String,
    val group: ZygiskSignalGroup,
    val severity: ZygiskSignalSeverity,
    val detail: String,
    val direct: Boolean,
    val detailMonospace: Boolean = false,
)

data class ZygiskMethodResult(
    val label: String,
    val summary: String,
    val outcome: ZygiskMethodOutcome,
    val detail: String,
)

data class ZygiskReport(
    val stage: ZygiskStage,
    val fdTrapAvailable: Boolean,
    val fdTrapDetected: Boolean,
    val nativeAvailable: Boolean,
    val heapAvailable: Boolean,
    val seccompSupported: Boolean,
    val nativeStrongHitCount: Int,
    val heuristicHitCount: Int,
    val tracerPid: Int,
    val signals: List<ZygiskSignal>,
    val methods: List<ZygiskMethodResult>,
    val references: List<String>,
    val errorMessage: String? = null,
) {
    val strongHitCount: Int
        get() = nativeStrongHitCount + if (fdTrapDetected) 1 else 0

    val dangerSignalCount: Int
        get() = signals.count { it.severity == ZygiskSignalSeverity.DANGER }

    val warningSignalCount: Int
        get() = signals.count { it.severity == ZygiskSignalSeverity.WARNING }

    val directSignalCount: Int
        get() = signals.count { it.direct }

    val supportOnly: Boolean
        get() = stage == ZygiskStage.READY &&
                !fdTrapDetected &&
                nativeStrongHitCount == 0 &&
                heuristicHitCount == 0 &&
                (!fdTrapAvailable || !nativeAvailable)

    val fullyClean: Boolean
        get() = stage == ZygiskStage.READY &&
                !fdTrapDetected &&
                nativeStrongHitCount == 0 &&
                heuristicHitCount == 0 &&
                fdTrapAvailable &&
                nativeAvailable

    companion object {
        fun loading(): ZygiskReport {
            return ZygiskReport(
                stage = ZygiskStage.LOADING,
                fdTrapAvailable = false,
                fdTrapDetected = false,
                nativeAvailable = false,
                heapAvailable = false,
                seccompSupported = false,
                nativeStrongHitCount = 0,
                heuristicHitCount = 0,
                tracerPid = 0,
                signals = emptyList(),
                methods = emptyList(),
                references = defaultReferences(),
            )
        }

        fun failed(message: String): ZygiskReport {
            return loading().copy(
                stage = ZygiskStage.FAILED,
                errorMessage = message,
            )
        }

        fun defaultReferences(): List<String> {
            return listOf(
                "Cross-process FD trap looks for deleted-path descriptors that should survive clean specialization but may be silently closed by Zygisk-style FD sanitization.",
                "Native runtime probes correlate linker ownership, restricted-path loading, /proc maps and smaps drift, suspicious thread or fd residue, seccomp trap behavior, and heap entropy.",
                "Read this card together with Mount and Memory because those cards can still show corroborating Zygisk-facing traces even when this process keeps only partial residue.",
            )
        }
    }
}
