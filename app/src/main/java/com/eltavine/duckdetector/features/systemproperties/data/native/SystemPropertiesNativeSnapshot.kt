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

package com.eltavine.duckdetector.features.systemproperties.data.native

import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySource

data class PropAreaFinding(
    val context: String,
    val holeCount: Int,
    val detail: String,
)

data class ReadOnlyPropertySerialFinding(
    val property: String,
    val suspiciousSampleCount: Int,
    val low24Hex: String,
    val detail: String,
)

data class SystemPropertiesNativeSnapshot(
    val available: Boolean = false,
    val libcProperties: Map<String, String> = emptyMap(),
    val cmdlineBootParams: Map<String, String> = emptyMap(),
    val bootconfigBootParams: Map<String, String> = emptyMap(),
    val rawCmdline: String = "",
    val rawBootconfig: String = "",
    val propAreaAvailable: Boolean = false,
    val propAreaContextCount: Int = 0,
    val propAreaHoleCount: Int = 0,
    val propAreaFindings: List<PropAreaFinding> = emptyList(),
    val readOnlySerialAvailable: Boolean = false,
    val readOnlySerialCheckedCount: Int = 0,
    val readOnlySerialFindingCount: Int = 0,
    val readOnlySerialFindings: List<ReadOnlyPropertySerialFinding> = emptyList(),
) {
    val nativePropertyHitCount: Int
        get() = libcProperties.values.count { sanitizeLibcValue(it).isNotBlank() }

    val bootParamHitCount: Int
        get() = (cmdlineBootParams.keys + bootconfigBootParams.keys).toSet().size

    fun libcValue(
        property: String,
    ): String {
        return sanitizeLibcValue(libcProperties[property])
    }

    fun findBootValueForProperty(
        property: String,
    ): Pair<SystemPropertySource, String>? {
        val bootKey = propertyToBootKey(property) ?: return null
        bootconfigBootParams[bootKey]
            ?.takeIf { it.isNotBlank() }
            ?.let { return SystemPropertySource.BOOTCONFIG to it }
        cmdlineBootParams[bootKey]
            ?.takeIf { it.isNotBlank() }
            ?.let { return SystemPropertySource.CMDLINE to it }
        return null
    }

    private fun propertyToBootKey(
        property: String,
    ): String? {
        if (!property.startsWith(RO_BOOT_PREFIX)) {
            return null
        }
        return ANDROIDBOOT_PREFIX + property.removePrefix(RO_BOOT_PREFIX)
    }

    private companion object {
        private const val RO_BOOT_PREFIX = "ro.boot."
        private const val ANDROIDBOOT_PREFIX = "androidboot."
        private const val CALLBACK_REQUIRED_MESSAGE =
            "Must use __system_property_read_callback() to read"
    }

    private fun sanitizeLibcValue(
        value: String?,
    ): String {
        val trimmed = value?.trim().orEmpty()
        return if (trimmed.contains(CALLBACK_REQUIRED_MESSAGE, ignoreCase = true)) {
            ""
        } else {
            trimmed
        }
    }
}
