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

package com.eltavine.duckdetector.features.lsposed.domain

enum class LSPosedStage {
    LOADING,
    READY,
    FAILED,
}

enum class LSPosedSignalGroup {
    RUNTIME,
    PACKAGES,
    BINDER,
    NATIVE,
}

enum class LSPosedSignalSeverity(
    val label: String,
) {
    DANGER("Danger"),
    WARNING("Review"),
}

enum class LSPosedMethodOutcome {
    CLEAN,
    WARNING,
    DETECTED,
    SUPPORT,
}

enum class LSPosedPackageVisibility {
    FULL,
    RESTRICTED,
    UNKNOWN,
}

data class LSPosedSignal(
    val id: String,
    val label: String,
    val value: String,
    val group: LSPosedSignalGroup,
    val severity: LSPosedSignalSeverity,
    val detail: String,
    val detailMonospace: Boolean = false,
)

data class LSPosedMethodResult(
    val label: String,
    val summary: String,
    val outcome: LSPosedMethodOutcome,
    val detail: String,
)

data class LSPosedReport(
    val stage: LSPosedStage,
    val nativeAvailable: Boolean,
    val runtimeArtifactAvailable: Boolean,
    val logcatAvailable: Boolean,
    val packageVisibility: LSPosedPackageVisibility,
    val signals: List<LSPosedSignal>,
    val methods: List<LSPosedMethodResult>,
    val managerPackageCount: Int,
    val moduleAppCount: Int,
    val classHitCount: Int,
    val classLoaderHitCount: Int,
    val bridgeFieldHitCount: Int,
    val stackHitCount: Int,
    val callbackHitCount: Int,
    val binderHitCount: Int,
    val runtimeArtifactHitCount: Int,
    val logcatHitCount: Int,
    val nativeMapsHitCount: Int,
    val nativeHeapHitCount: Int,
    val nativeHeapScannedRegions: Int,
    val errorMessage: String? = null,
) {
    val dangerSignalCount: Int
        get() = signals.count { it.severity == LSPosedSignalSeverity.DANGER }

    val warningSignalCount: Int
        get() = signals.count { it.severity == LSPosedSignalSeverity.WARNING }

    val runtimeSignalCount: Int
        get() = signals.count {
            it.group == LSPosedSignalGroup.RUNTIME ||
                    it.group == LSPosedSignalGroup.BINDER ||
                    it.group == LSPosedSignalGroup.NATIVE
        }

    val packageSignalCount: Int
        get() = signals.count { it.group == LSPosedSignalGroup.PACKAGES }

    val nativeTraceCount: Int
        get() = signals.count { it.group == LSPosedSignalGroup.NATIVE }

    val hasDangerSignals: Boolean
        get() = dangerSignalCount > 0

    val hasWarningSignals: Boolean
        get() = warningSignalCount > 0

    companion object {
        fun loading(): LSPosedReport {
            return LSPosedReport(
                stage = LSPosedStage.LOADING,
                nativeAvailable = true,
                runtimeArtifactAvailable = true,
                logcatAvailable = true,
                packageVisibility = LSPosedPackageVisibility.UNKNOWN,
                signals = emptyList(),
                methods = emptyList(),
                managerPackageCount = 0,
                moduleAppCount = 0,
                classHitCount = 0,
                classLoaderHitCount = 0,
                bridgeFieldHitCount = 0,
                stackHitCount = 0,
                callbackHitCount = 0,
                binderHitCount = 0,
                runtimeArtifactHitCount = 0,
                logcatHitCount = 0,
                nativeMapsHitCount = 0,
                nativeHeapHitCount = 0,
                nativeHeapScannedRegions = 0,
            )
        }

        fun failed(message: String): LSPosedReport {
            return loading().copy(
                stage = LSPosedStage.FAILED,
                nativeAvailable = false,
                errorMessage = message,
            )
        }
    }
}
