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

package com.eltavine.duckdetector.features.lsposed.data.art

import java.lang.reflect.Method

class ArtMethodNativeBridge {

    fun collectSnapshot(): ArtMethodSnapshot {
        return parse(collectRawSnapshot())
    }

    internal fun collectRawSnapshot(): String {
        val targets = ArtMethodTargetCatalog.targets()
        return runCatching {
            nativeCollectSnapshot(
                targets.map { it.method }.toTypedArray(),
                targets.map { it.label }.toTypedArray(),
            )
        }.getOrDefault("")
    }

    internal fun parse(raw: String): ArtMethodSnapshot {
        if (raw.isBlank()) {
            return ArtMethodSnapshot()
        }

        var available = false
        val methodBuilders = linkedMapOf<String, MutableMethodEntry>()
        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when {
                    line.startsWith("METHOD=") -> {
                        val parts = line.removePrefix("METHOD=").split('\t', limit = 3)
                        if (parts.size == 3) {
                            val label = parts[0].decodeValue()
                            methodBuilders[label] = MutableMethodEntry(
                                label = label,
                                artMethodAddress = parts[1],
                                declaredCandidateCount = parts[2].toIntOrNull() ?: 0,
                            )
                        }
                    }

                    line.startsWith("CANDIDATE=") -> {
                        val parts = line.removePrefix("CANDIDATE=").split('\t', limit = 10)
                        if (parts.size == 10) {
                            val label = parts[0].decodeValue()
                            methodBuilders.getOrPut(label) {
                                MutableMethodEntry(
                                    label = label,
                                    artMethodAddress = "",
                                    declaredCandidateCount = 0,
                                )
                            }.candidates += ArtMethodCandidate(
                                label = label,
                                offset = parts[1].toIntOrNull() ?: -1,
                                address = parts[2],
                                regionKind = parts[3],
                                mapStart = parts[4],
                                mapOffset = parts[5],
                                permissions = parts[6],
                                suspicious = parts[7].asBool(),
                                path = parts[8].decodeValue(),
                                detail = parts[9].decodeValue(),
                            )
                        }
                    }

                    line.contains('=') -> {
                        val key = line.substringBefore('=')
                        val value = line.substringAfter('=')
                        if (key == "AVAILABLE") {
                            available = value.asBool()
                        }
                    }
                }
            }

        val methods = methodBuilders.values.map { builder ->
            ArtMethodEntry(
                label = builder.label,
                artMethodAddress = builder.artMethodAddress,
                declaredCandidateCount = builder.declaredCandidateCount,
                candidates = builder.candidates.sortedBy { it.offset },
            )
        }

        return ArtMethodSnapshot(
            available = available,
            methodCount = methods.size,
            candidateCount = methods.sumOf { it.candidates.size },
            suspiciousCandidateCount = methods.sumOf { method ->
                method.candidates.count { it.suspicious }
            },
            methods = methods,
        )
    }

    private data class MutableMethodEntry(
        val label: String,
        val artMethodAddress: String,
        val declaredCandidateCount: Int,
        val candidates: MutableList<ArtMethodCandidate> = mutableListOf(),
    )

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

    private external fun nativeCollectSnapshot(
        methods: Array<Method>,
        labels: Array<String>,
    ): String

    companion object {
        init {
            runCatching { System.loadLibrary("duckdetector") }
        }
    }
}

internal data class ArtMethodProbeTarget(
    val label: String,
    val method: Method,
)

internal object ArtMethodTargetCatalog {
    fun targets(): List<ArtMethodProbeTarget> {
        val clazz = ArtMethodSentinel::class.java
        val intType = requireNotNull(Int::class.javaPrimitiveType)
        return listOf(
            ArtMethodProbeTarget(
                label = "staticToken",
                method = clazz.getDeclaredMethod("staticToken", intType),
            ),
            ArtMethodProbeTarget(
                label = "virtualToken",
                method = clazz.getDeclaredMethod("virtualToken", intType),
            ),
            ArtMethodProbeTarget(
                label = "stringToken",
                method = clazz.getDeclaredMethod("stringToken", String::class.java),
            ),
        )
    }
}
