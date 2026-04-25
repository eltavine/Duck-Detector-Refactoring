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

package com.eltavine.duckdetector.features.lsposed.data.probes

import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity

data class LSPosedBridgeFieldProbeResult(
    val signals: List<LSPosedSignal>,
    val hitCount: Int,
)

class LSPosedBridgeFieldProbe {

    fun run(): LSPosedBridgeFieldProbeResult {
        return evaluate(TARGET_CLASS_NAME)
    }

    internal fun evaluate(
        targetClassName: String,
    ): LSPosedBridgeFieldProbeResult {
        val xposedBridgeClass = runCatching {
            Class.forName(targetClassName)
        }.getOrNull() ?: return LSPosedBridgeFieldProbeResult(
            signals = emptyList(),
            hitCount = 0,
        )

        val signals = FIELD_NAMES.mapNotNull { fieldName ->
            runCatching {
                val field = xposedBridgeClass.getDeclaredField(fieldName)
                field.isAccessible = true
                val value = runCatching { field.get(null) }.getOrNull()
                LSPosedSignal(
                    id = "bridge_field_${fieldName.toSignalIdSegment()}",
                    label = "XposedBridge field",
                    value = fieldName,
                    group = LSPosedSignalGroup.RUNTIME,
                    severity = LSPosedSignalSeverity.DANGER,
                    detail = buildString {
                        appendLine("Field: $fieldName")
                        append("Value: ")
                        append(value?.javaClass?.name ?: value?.toString() ?: "null")
                    },
                    detailMonospace = true,
                )
            }.getOrNull()
        }

        return LSPosedBridgeFieldProbeResult(
            signals = signals,
            hitCount = signals.size,
        )
    }

    private companion object {
        private const val TARGET_CLASS_NAME = "de.robv.android.xposed.XposedBridge"

        private val FIELD_NAMES = listOf(
            "disableHooks",
            "sHookedMethodCallbacks",
        )
    }
}
