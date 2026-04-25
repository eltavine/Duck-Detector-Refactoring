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

package com.eltavine.duckdetector.features.playintegrityfix.data.utils

import com.eltavine.duckdetector.features.playintegrityfix.data.native.PlayIntegrityFixNativeBridge
import com.eltavine.duckdetector.features.playintegrityfix.data.native.PlayIntegrityFixNativeSnapshot
import com.eltavine.duckdetector.features.playintegrityfix.data.rules.PlayIntegrityFixPropertyRule
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixSource
import java.util.concurrent.TimeUnit

data class PlayIntegrityMultiSourceRead(
    val rule: PlayIntegrityFixPropertyRule,
    val preferredValue: String,
    val preferredSource: PlayIntegrityFixSource,
    val sourceValues: Map<PlayIntegrityFixSource, String>,
)

class PlayIntegrityPropertyReadUtils(
    private val nativeBridge: PlayIntegrityFixNativeBridge = PlayIntegrityFixNativeBridge(),
) {
    private var getpropSnapshot: Map<String, String>? = null

    fun collectNativeSnapshot(
        propertyNames: Collection<String>,
    ): PlayIntegrityFixNativeSnapshot {
        return nativeBridge.collectSnapshot(propertyNames)
    }

    fun readProperty(
        rule: PlayIntegrityFixPropertyRule,
        cache: MutableMap<String, PlayIntegrityMultiSourceRead>,
        nativeSnapshot: PlayIntegrityFixNativeSnapshot,
    ): PlayIntegrityMultiSourceRead {
        return cache.getOrPut(rule.property) {
            val sourceValues = linkedMapOf<PlayIntegrityFixSource, String>()
            sourceValues[PlayIntegrityFixSource.REFLECTION] = readViaReflection(rule.property)
            sourceValues[PlayIntegrityFixSource.GETPROP] = readViaGetprop(rule.property)
            sourceValues[PlayIntegrityFixSource.JVM] = readViaJvm(rule.property)
            sourceValues[PlayIntegrityFixSource.NATIVE_LIBC] =
                nativeSnapshot.nativeProperties[rule.property].orEmpty()

            val preferredSource = listOf(
                PlayIntegrityFixSource.REFLECTION,
                PlayIntegrityFixSource.GETPROP,
                PlayIntegrityFixSource.NATIVE_LIBC,
                PlayIntegrityFixSource.JVM,
            ).firstOrNull { sourceValues[it].isNullOrBlank().not() }
                ?: PlayIntegrityFixSource.REFLECTION

            PlayIntegrityMultiSourceRead(
                rule = rule,
                preferredValue = sourceValues[preferredSource].orEmpty(),
                preferredSource = preferredSource,
                sourceValues = sourceValues,
            )
        }
    }

    private fun readViaReflection(property: String): String {
        return runCatching {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java)
            (method.invoke(null, property) as? String)?.trim().orEmpty()
        }.getOrDefault("")
    }

    private fun readViaGetprop(property: String): String {
        val snapshot = getpropSnapshot ?: readGetpropSnapshot().also { getpropSnapshot = it }
        return snapshot[property].orEmpty()
    }

    private fun readViaJvm(property: String): String {
        return runCatching { System.getProperty(property)?.trim().orEmpty() }
            .getOrDefault("")
    }

    private fun readGetpropSnapshot(): Map<String, String> {
        var process: Process? = null
        return try {
            process = ProcessBuilder("getprop")
                .redirectErrorStream(true)
                .start()
            val parsed = process.inputStream.bufferedReader().useLines { lines ->
                lines.mapNotNull(::parseGetpropLine).toMap(linkedMapOf())
            }
            if (!process.waitFor(2, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                emptyMap()
            } else {
                parsed
            }
        } catch (_: Exception) {
            emptyMap()
        } finally {
            process?.destroy()
        }
    }

    private fun parseGetpropLine(line: String): Pair<String, String>? {
        val trimmed = line.trim()
        if (trimmed.isEmpty()) {
            return null
        }
        val bracket = BRACKET_PATTERN.matchEntire(trimmed)
        if (bracket != null) {
            return bracket.groupValues[1] to bracket.groupValues[2]
        }
        if (!trimmed.contains('=')) {
            return null
        }
        return trimmed.substringBefore('=').trim() to trimmed.substringAfter('=').trim()
    }

    private companion object {
        private val BRACKET_PATTERN = Regex("""^\[(.+?)]\s*:\s*\[(.*)]$""")
    }
}
