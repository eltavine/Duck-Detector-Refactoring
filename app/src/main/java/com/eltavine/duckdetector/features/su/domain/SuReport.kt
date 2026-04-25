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

package com.eltavine.duckdetector.features.su.domain

enum class SuStage {
    LOADING,
    READY,
    FAILED,
}

enum class SuMethodOutcome {
    CLEAN,
    DETECTED,
    SUPPORT,
}

data class SuDaemonFinding(
    val name: String,
    val path: String,
)

data class SuMethodResult(
    val label: String,
    val summary: String,
    val outcome: SuMethodOutcome,
    val detail: String? = null,
)

data class SuReport(
    val stage: SuStage,
    val suBinaries: List<String>,
    val daemons: List<SuDaemonFinding>,
    val selfContext: String,
    val selfContextAbnormal: Boolean,
    val suspiciousProcesses: List<String>,
    val nativeAvailable: Boolean,
    val checkedSuPathCount: Int,
    val checkedDaemonPathCount: Int,
    val checkedProcessCount: Int,
    val deniedProcessCount: Int,
    val methods: List<SuMethodResult>,
    val errorMessage: String? = null,
) {
    val hasRootIndicators: Boolean
        get() = suBinaries.isNotEmpty() || daemons.isNotEmpty() || selfContextAbnormal || suspiciousProcesses.isNotEmpty()

    companion object {
        fun loading(): SuReport {
            return SuReport(
                stage = SuStage.LOADING,
                suBinaries = emptyList(),
                daemons = emptyList(),
                selfContext = "",
                selfContextAbnormal = false,
                suspiciousProcesses = emptyList(),
                nativeAvailable = true,
                checkedSuPathCount = 0,
                checkedDaemonPathCount = 0,
                checkedProcessCount = 0,
                deniedProcessCount = 0,
                methods = emptyList(),
            )
        }

        fun failed(message: String): SuReport {
            return SuReport(
                stage = SuStage.FAILED,
                suBinaries = emptyList(),
                daemons = emptyList(),
                selfContext = "",
                selfContextAbnormal = false,
                suspiciousProcesses = emptyList(),
                nativeAvailable = false,
                checkedSuPathCount = 0,
                checkedDaemonPathCount = 0,
                checkedProcessCount = 0,
                deniedProcessCount = 0,
                methods = emptyList(),
                errorMessage = message,
            )
        }
    }
}
