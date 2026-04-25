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

package com.eltavine.duckdetector.features.lsposed.data.native

class LSPosedNativeBridge {

    fun collectSnapshot(): LSPosedNativeSnapshot {
        return runCatching {
            parse(nativeCollectSnapshot())
        }.getOrDefault(LSPosedNativeSnapshot())
    }

    internal fun parse(raw: String): LSPosedNativeSnapshot {
        if (raw.isBlank()) {
            return LSPosedNativeSnapshot()
        }

        var snapshot = LSPosedNativeSnapshot()
        val traces = mutableListOf<LSPosedNativeTrace>()

        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when {
                    line.startsWith("TRACE=") -> {
                        val parts = line.removePrefix("TRACE=").split('\t', limit = 4)
                        if (parts.size == 4) {
                            traces += LSPosedNativeTrace(
                                group = parts[0],
                                severity = parts[1],
                                label = parts[2].decodeValue(),
                                detail = parts[3].decodeValue(),
                            )
                        }
                    }

                    line.contains('=') -> {
                        val key = line.substringBefore('=')
                        val value = line.substringAfter('=')
                        snapshot = snapshot.applyEntry(key, value)
                    }
                }
            }

        return snapshot.copy(traces = traces)
    }

    private fun LSPosedNativeSnapshot.applyEntry(
        key: String,
        value: String,
    ): LSPosedNativeSnapshot {
        return when (key) {
            "AVAILABLE" -> copy(available = value.asBool())
            "HEAP_AVAILABLE" -> copy(heapAvailable = value.asBool())
            "MAPS_HITS" -> copy(mapsHitCount = value.toIntOrNull() ?: mapsHitCount)
            "MAPS_SCANNED" -> copy(mapsScannedLines = value.toIntOrNull() ?: mapsScannedLines)
            "HEAP_HITS" -> copy(heapHitCount = value.toIntOrNull() ?: heapHitCount)
            "HEAP_SCANNED" -> copy(heapScannedRegions = value.toIntOrNull() ?: heapScannedRegions)
            else -> this
        }
    }

    private fun String.asBool(): Boolean {
        return this == "1" || equals("true", ignoreCase = true)
    }

    private fun String.decodeValue(): String {
        return buildString(length) {
            var index = 0
            while (index < this@decodeValue.length) {
                val current = this@decodeValue[index]
                if (current == '\\' && index + 1 < this@decodeValue.length) {
                    when (this@decodeValue[index + 1]) {
                        'n' -> {
                            append('\n')
                            index += 2
                            continue
                        }

                        'r' -> {
                            append('\r')
                            index += 2
                            continue
                        }

                        't' -> {
                            append('\t')
                            index += 2
                            continue
                        }

                        '\\' -> {
                            append('\\')
                            index += 2
                            continue
                        }
                    }
                }
                append(current)
                index += 1
            }
        }
    }

    private external fun nativeCollectSnapshot(): String

    companion object {
        init {
            runCatching { System.loadLibrary("duckdetector") }
        }
    }
}
