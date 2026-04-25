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

package com.eltavine.duckdetector.features.playintegrityfix.data.native

class PlayIntegrityFixNativeBridge {

    fun collectSnapshot(
        propertyNames: Collection<String>,
    ): PlayIntegrityFixNativeSnapshot {
        return runCatching {
            parse(nativeCollectSnapshot(propertyNames.distinct().sorted().toTypedArray()))
        }.getOrDefault(PlayIntegrityFixNativeSnapshot())
    }

    internal fun parse(raw: String): PlayIntegrityFixNativeSnapshot {
        if (raw.isBlank()) {
            return PlayIntegrityFixNativeSnapshot()
        }

        var available = false
        val properties = linkedMapOf<String, String>()
        val traces = mutableListOf<PlayIntegrityFixNativeTrace>()

        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && it.contains('=') }
            .forEach { line ->
                val key = line.substringBefore('=')
                val value = line.substringAfter('=')
                when (key) {
                    "AVAILABLE" -> available =
                        value == "1" || value.equals("true", ignoreCase = true)

                    "PROP" -> {
                        val parts = value.split('|', limit = 2)
                        if (parts.size == 2) {
                            properties[parts[0]] = parts[1].decodeValue()
                        }
                    }

                    "TRACE" -> {
                        val parts = value.split('\t', limit = 3)
                        if (parts.size == 3) {
                            traces += PlayIntegrityFixNativeTrace(
                                severity = parts[0],
                                label = parts[1],
                                detail = parts[2].decodeValue(),
                            )
                        }
                    }
                }
            }

        return PlayIntegrityFixNativeSnapshot(
            available = available,
            nativeProperties = properties,
            runtimeTraces = traces,
        )
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

    private external fun nativeCollectSnapshot(propertyNames: Array<String>): String

    companion object {
        init {
            runCatching { System.loadLibrary("duckdetector") }
        }
    }
}
