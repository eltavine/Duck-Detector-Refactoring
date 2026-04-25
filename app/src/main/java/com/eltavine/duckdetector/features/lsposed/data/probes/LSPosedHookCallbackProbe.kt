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

data class LSPosedHookCallbackProbeResult(
    val signals: List<LSPosedSignal>,
    val hitCount: Int,
)

class LSPosedHookCallbackProbe {

    fun run(): LSPosedHookCallbackProbeResult {
        return evaluate(Thread.getDefaultUncaughtExceptionHandler())
    }

    internal fun evaluate(
        handler: Thread.UncaughtExceptionHandler?,
    ): LSPosedHookCallbackProbeResult {
        val handlerClassName = handler?.javaClass?.name
            ?.takeIf(::containsFrameworkToken)
            ?: return LSPosedHookCallbackProbeResult(
                signals = emptyList(),
                hitCount = 0,
            )

        val signal = LSPosedSignal(
            id = "hook_callback_handler",
            label = "Default exception handler",
            value = "Injected",
            group = LSPosedSignalGroup.RUNTIME,
            severity = LSPosedSignalSeverity.DANGER,
            detail = handlerClassName,
            detailMonospace = true,
        )

        return LSPosedHookCallbackProbeResult(
            signals = listOf(signal),
            hitCount = 1,
        )
    }
}
