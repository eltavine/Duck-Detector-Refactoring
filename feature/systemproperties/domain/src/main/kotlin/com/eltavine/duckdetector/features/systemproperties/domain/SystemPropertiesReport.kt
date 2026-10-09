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

package com.eltavine.duckdetector.features.systemproperties.domain

import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySignal

enum class SystemPropertiesStage {
    LOADING,
    READY,
    FAILED,
}

enum class SystemPropertiesMethodOutcome {
    CLEAN,
    WARNING,
    DANGER,
    SUPPORT,
}

data class SystemPropertiesMethodResult(
    val label: String,
    val summary: String,
    val outcome: SystemPropertiesMethodOutcome,
    val detail: String? = null,
)

/** The debug, system and radio property-area modification times, compared once per scan. */
sealed interface PropertyAreaClocks {
    /** System is newer than debug and debug is newer than radio; debug minus radio in nanoseconds. */
    data class Ordered(val debugMinusRadioNanos: Long) : PropertyAreaClocks

    /** All three were read and that order does not hold. */
    data object NotOrdered : PropertyAreaClocks

    /** At least one of the three files could not be stat'ed, so no order was compared. */
    data object Unreadable : PropertyAreaClocks
}

data class SystemPropertiesReport(
    val stage: SystemPropertiesStage,
    /** Signals about individual properties, their sources and how those sources agree. */
    val propertySignals: List<SystemPropertySignal>,
    /** One signal per property context whose raw property area has holes. */
    val propAreaSignals: List<SystemPropertySignal>,
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
    val methods: List<SystemPropertiesMethodResult>,
    val errorMessage: String? = null,
    /** Null when the comparison was not run. */
    val propertyAreaClocks: PropertyAreaClocks? = null,
) {
    val signals: List<SystemPropertySignal>
        get() = propertySignals + propAreaSignals

    val dangerSignals: List<SystemPropertySignal>
        get() = signals.filter { it.severity == SystemPropertySeverity.DANGER }

    val warningSignals: List<SystemPropertySignal>
        get() = signals.filter { it.severity == SystemPropertySeverity.WARNING }

    val hasDangerSignals: Boolean
        get() = dangerSignals.isNotEmpty()

    val hasPropertyAreaAnomaly: Boolean
        get() = propertyAreaClocks is PropertyAreaClocks.Ordered

    /** Warning signals plus an ordered property-area clock gap, which is not a property signal. */
    val reviewCount: Int
        get() = warningSignals.size + if (hasPropertyAreaAnomaly) 1 else 0

    val hasWarningSignals: Boolean
        get() = reviewCount > 0

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
                propertySignals = emptyList(),
                propAreaSignals = emptyList(),
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
                methods = emptyList(),
            )
        }

        fun failed(message: String): SystemPropertiesReport {
            return SystemPropertiesReport(
                stage = SystemPropertiesStage.FAILED,
                propertySignals = emptyList(),
                propAreaSignals = emptyList(),
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
                methods = emptyList(),
                errorMessage = message,
            )
        }
    }
}
