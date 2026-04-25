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

package com.eltavine.duckdetector.features.playintegrityfix.domain

enum class PlayIntegrityFixStage {
    LOADING,
    READY,
    FAILED,
}

enum class PlayIntegrityFixGroup {
    PROPERTIES,
    CONSISTENCY,
    NATIVE,
}

enum class PlayIntegrityFixPropertyCategory(
    val label: String,
) {
    CONTROL("Spoof control"),
    PIXEL("Pixel props"),
    DEVICE("Device spoof"),
    SECURITY("Security spoof"),
    RUNTIME("Runtime trace"),
}

enum class PlayIntegrityFixSource(
    val label: String,
) {
    REFLECTION("Reflection"),
    GETPROP("getprop"),
    JVM("JVM"),
    NATIVE_LIBC("Native libc"),
    NATIVE_MAPS("Native maps"),
}

enum class PlayIntegrityFixSignalSeverity(
    val label: String,
) {
    DANGER("Danger"),
    WARNING("Review"),
}

enum class PlayIntegrityFixMethodOutcome {
    CLEAN,
    DETECTED,
    WARNING,
    SUPPORT,
}

data class PlayIntegrityFixSignal(
    val id: String,
    val label: String,
    val value: String,
    val group: PlayIntegrityFixGroup,
    val category: PlayIntegrityFixPropertyCategory,
    val severity: PlayIntegrityFixSignalSeverity,
    val source: PlayIntegrityFixSource,
    val detail: String,
    val detailMonospace: Boolean = false,
)

data class PlayIntegrityFixMethodResult(
    val label: String,
    val summary: String,
    val outcome: PlayIntegrityFixMethodOutcome,
    val detail: String,
)

data class PlayIntegrityFixReport(
    val stage: PlayIntegrityFixStage,
    val propertySignals: List<PlayIntegrityFixSignal>,
    val consistencySignals: List<PlayIntegrityFixSignal>,
    val nativeSignals: List<PlayIntegrityFixSignal>,
    val checkedPropertyCount: Int,
    val reflectionHitCount: Int,
    val getpropHitCount: Int,
    val jvmHitCount: Int,
    val nativePropertyHitCount: Int,
    val nativeTraceCount: Int,
    val nativeAvailable: Boolean,
    val methods: List<PlayIntegrityFixMethodResult>,
    val errorMessage: String? = null,
) {
    val dangerSignalCount: Int
        get() = (propertySignals + consistencySignals + nativeSignals).count {
            it.severity == PlayIntegrityFixSignalSeverity.DANGER
        }

    val warningSignalCount: Int
        get() = (propertySignals + consistencySignals + nativeSignals).count {
            it.severity == PlayIntegrityFixSignalSeverity.WARNING
        }

    val directPropertyCount: Int
        get() = propertySignals.size

    val runtimeSignalCount: Int
        get() = nativeSignals.size

    val hasIndicators: Boolean
        get() = directPropertyCount > 0 || consistencySignals.isNotEmpty() || nativeSignals.isNotEmpty()

    companion object {
        fun loading(): PlayIntegrityFixReport {
            return PlayIntegrityFixReport(
                stage = PlayIntegrityFixStage.LOADING,
                propertySignals = emptyList(),
                consistencySignals = emptyList(),
                nativeSignals = emptyList(),
                checkedPropertyCount = 0,
                reflectionHitCount = 0,
                getpropHitCount = 0,
                jvmHitCount = 0,
                nativePropertyHitCount = 0,
                nativeTraceCount = 0,
                nativeAvailable = true,
                methods = emptyList(),
            )
        }

        fun failed(message: String): PlayIntegrityFixReport {
            return loading().copy(
                stage = PlayIntegrityFixStage.FAILED,
                nativeAvailable = false,
                errorMessage = message,
            )
        }
    }
}
