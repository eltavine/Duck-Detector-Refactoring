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

package com.eltavine.duckdetector.features.tee.data.native

class TeeRegisterTimerNativeBridge {

    fun isNativeAvailable(): Boolean = nativeLoaded

    fun isRegisterTimerAvailable(): Boolean {
        if (!nativeLoaded) {
            return false
        }
        return runCatching {
            nativeIsRegisterTimerAvailable()
        }.getOrDefault(false)
    }

    fun readRegisterTimerNs(): Long? {
        if (!nativeLoaded) {
            return null
        }
        return runCatching {
            nativeReadRegisterTimerNs().takeIf { it >= 0L }
        }.getOrNull()
    }

    fun bindCurrentThreadToCpu0(): Boolean {
        if (!nativeLoaded) {
            return false
        }
        return runCatching {
            nativeBindCurrentThreadToCpu0()
        }.getOrDefault(false)
    }

    fun selectPreferredTimer(requestCpu0Affinity: Boolean = true): TeeRegisterTimerSelection {
        if (!nativeLoaded) {
            return TeeRegisterTimerSelection(
                fallbackReason = "native bridge unavailable",
                affinityStatus = if (requestCpu0Affinity) "native_unavailable" else "not_requested",
            )
        }
        return runCatching {
            parseSelection(nativeSelectPreferredTimer(requestCpu0Affinity))
        }.getOrDefault(
            TeeRegisterTimerSelection(
                fallbackReason = "timer selection failed",
                affinityStatus = if (requestCpu0Affinity) "selection_failed" else "not_requested",
            ),
        )
    }

    internal fun parseSelection(raw: String): TeeRegisterTimerSelection {
        val values = parseKeyValueLines(raw)
        return TeeRegisterTimerSelection(
            registerTimerAvailable = values["REGISTER_TIMER_AVAILABLE"].asBool(),
            timerSource = values["TIMER_SOURCE"] ?: "clock_monotonic",
            fallbackReason = values["FALLBACK_REASON"]?.takeIf { it.isNotBlank() },
            affinityStatus = values["AFFINITY"] ?: "not_requested",
        )
    }

    private fun parseKeyValueLines(raw: String): Map<String, String> {
        return buildMap {
            raw.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() && it.contains('=') }
                .forEach { line ->
                    put(line.substringBefore('='), line.substringAfter('='))
                }
        }
    }

    private fun String?.asBool(): Boolean {
        return this == "1" || this.equals("true", ignoreCase = true)
    }

    private external fun nativeIsRegisterTimerAvailable(): Boolean

    private external fun nativeReadRegisterTimerNs(): Long

    private external fun nativeBindCurrentThreadToCpu0(): Boolean

    private external fun nativeSelectPreferredTimer(requestCpu0Affinity: Boolean): String

    companion object {
        private val nativeLoaded = runCatching { System.loadLibrary("duckdetector") }.isSuccess
    }
}
