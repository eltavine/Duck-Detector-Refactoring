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

package com.eltavine.duckdetector.features.kernelcheck.data.native

class KernelCheckNativeBridge {

    fun collectSnapshot(
        systemBuildTime: Long,
    ): KernelCheckNativeSnapshot {
        return runCatching {
            parse(nativeCollectSnapshot(systemBuildTime))
        }.getOrDefault(KernelCheckNativeSnapshot())
    }

    internal fun parse(
        raw: String,
    ): KernelCheckNativeSnapshot {
        if (raw.isBlank()) {
            return KernelCheckNativeSnapshot()
        }

        val entries = raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && it.contains('=') }
            .map { it.substringBefore('=') to it.substringAfter('=') }
            .toList()

        return KernelCheckNativeSnapshot(
            available = entries.firstOrNull { it.first == "AVAILABLE" }?.second != "0",
            procVersion = entries.firstOrNull { it.first == "PROC_VERSION" }?.second?.decodeValue()
                .orEmpty(),
            procCmdline = entries.firstOrNull { it.first == "PROC_CMDLINE" }?.second?.decodeValue()
                .orEmpty(),
            suspiciousCmdline = entries.firstOrNull { it.first == "CMDLINE" }?.second == "1",
            buildTimeMismatch = entries.firstOrNull { it.first == "BUILD_TIME" }?.second == "1",
            kptrExposed = entries.firstOrNull { it.first == "KPTR" }?.second == "1",
            findings = entries.filter { it.first == "FINDING" }.map { it.second.decodeValue() },
        )
    }

    private fun String.decodeValue(): String {
        return replace("\\n", "\n")
            .replace("\\r", "\r")
    }

    private external fun nativeCollectSnapshot(systemBuildTime: Long): String

    companion object {
        init {
            runCatching { System.loadLibrary("duckdetector") }
        }
    }
}
