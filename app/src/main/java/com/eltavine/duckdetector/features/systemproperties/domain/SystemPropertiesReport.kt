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

package com.eltavine.duckdetector.features.systemproperties.domain

enum class SystemPropertiesStage {
    LOADING,
    READY,
    FAILED,
}

enum class SystemPropertySeverity {
    SAFE,
    WARNING,
    DANGER,
    NEUTRAL,
}

enum class SystemPropertyCategory {
    SECURITY_CORE,
    VERIFIED_BOOT,
    PARTITION_VERITY,
    BUILD_PROFILE,
    ROOT_RUNTIME,
    CUSTOM_ROM,
    DEVICE_INFO,
    BUILD_FINGERPRINT,
    SOURCE_CONSISTENCY,
    PROPERTY_CONSISTENCY,
}

enum class SystemPropertySource {
    REFLECTION,
    GETPROP,
    JVM,
    BUILD,
    NATIVE_LIBC,
    CMDLINE,
    BOOTCONFIG,
}

enum class SystemPropertiesMethodOutcome {
    CLEAN,
    WARNING,
    DANGER,
    SUPPORT,
}

data class SystemPropertySignal(
    val property: String,
    val description: String,
    val value: String,
    val category: SystemPropertyCategory,
    val severity: SystemPropertySeverity,
    val source: SystemPropertySource,
    val detail: String? = null,
)

data class SystemPropertiesMethodResult(
    val label: String,
    val summary: String,
    val outcome: SystemPropertiesMethodOutcome,
    val detail: String? = null,
)

data class SystemPropertiesReport(
    val stage: SystemPropertiesStage,
    val signals: List<SystemPropertySignal>,
    val infoSignals: List<SystemPropertySignal>,
    val checkedRuleCount: Int,
    val observedRuleCount: Int,
    val infoPropertyCount: Int,
    val reflectionHitCount: Int,
    val getpropHitCount: Int,
    val jvmHitCount: Int,
    val nativeHitCount: Int,
    val bootParamHitCount: Int,
    val buildSignalCount: Int,
    val propAreaAvailable: Boolean,
    val propAreaContextCount: Int,
    val propAreaHoleCount: Int,
    val readOnlySerialAvailable: Boolean,
    val readOnlySerialCheckedCount: Int,
    val readOnlySerialFindingCount: Int,
    val methods: List<SystemPropertiesMethodResult>,
    val errorMessage: String? = null,
) {
    val dangerSignals: List<SystemPropertySignal>
        get() = signals.filter { it.severity == SystemPropertySeverity.DANGER }

    val warningSignals: List<SystemPropertySignal>
        get() = signals.filter { it.severity == SystemPropertySeverity.WARNING }

    val hasDangerSignals: Boolean
        get() = dangerSignals.isNotEmpty()

    val hasWarningSignals: Boolean
        get() = warningSignals.isNotEmpty()

    val bootSignalCount: Int
        get() = signals.count {
            (it.category == SystemPropertyCategory.VERIFIED_BOOT ||
                    it.category == SystemPropertyCategory.PARTITION_VERITY) &&
                    it.severity != SystemPropertySeverity.SAFE &&
                    it.severity != SystemPropertySeverity.NEUTRAL
        }

    val buildProfileSignalCount: Int
        get() = signals.count {
            it.category == SystemPropertyCategory.BUILD_PROFILE &&
                    it.severity != SystemPropertySeverity.SAFE &&
                    it.severity != SystemPropertySeverity.NEUTRAL
        }

    val sourceMismatchCount: Int
        get() = signals.count { it.category == SystemPropertyCategory.SOURCE_CONSISTENCY }

    val consistencySignalCount: Int
        get() = signals.count { it.category == SystemPropertyCategory.PROPERTY_CONSISTENCY }

    val runtimeSignalCount: Int
        get() = signals.count {
            (it.category == SystemPropertyCategory.SECURITY_CORE ||
                    it.category == SystemPropertyCategory.ROOT_RUNTIME ||
                    it.category == SystemPropertyCategory.CUSTOM_ROM) &&
                    it.severity != SystemPropertySeverity.SAFE &&
                    it.severity != SystemPropertySeverity.NEUTRAL
        }

    companion object {
        fun loading(): SystemPropertiesReport {
            return SystemPropertiesReport(
                stage = SystemPropertiesStage.LOADING,
                signals = emptyList(),
                infoSignals = emptyList(),
                checkedRuleCount = 0,
                observedRuleCount = 0,
                infoPropertyCount = 0,
                reflectionHitCount = 0,
                getpropHitCount = 0,
                jvmHitCount = 0,
                nativeHitCount = 0,
                bootParamHitCount = 0,
                buildSignalCount = 0,
                propAreaAvailable = false,
                propAreaContextCount = 0,
                propAreaHoleCount = 0,
                readOnlySerialAvailable = false,
                readOnlySerialCheckedCount = 0,
                readOnlySerialFindingCount = 0,
                methods = emptyList(),
            )
        }

        fun failed(message: String): SystemPropertiesReport {
            return SystemPropertiesReport(
                stage = SystemPropertiesStage.FAILED,
                signals = emptyList(),
                infoSignals = emptyList(),
                checkedRuleCount = 0,
                observedRuleCount = 0,
                infoPropertyCount = 0,
                reflectionHitCount = 0,
                getpropHitCount = 0,
                jvmHitCount = 0,
                nativeHitCount = 0,
                bootParamHitCount = 0,
                buildSignalCount = 0,
                propAreaAvailable = false,
                propAreaContextCount = 0,
                propAreaHoleCount = 0,
                readOnlySerialAvailable = false,
                readOnlySerialCheckedCount = 0,
                readOnlySerialFindingCount = 0,
                methods = emptyList(),
                errorMessage = message,
            )
        }
    }
}
