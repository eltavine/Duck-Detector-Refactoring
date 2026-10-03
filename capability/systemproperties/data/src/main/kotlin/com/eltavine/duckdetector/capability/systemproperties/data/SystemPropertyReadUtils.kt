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

package com.eltavine.duckdetector.capability.systemproperties.data

import com.eltavine.duckdetector.capability.systemproperties.domain.MultiSourcePropertyRead
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertiesNativeSnapshot
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySource
import com.eltavine.duckdetector.core.platform.HiddenSystemProperties
import java.util.concurrent.TimeUnit

public class SystemPropertyReadUtils(
    private val nativeBridge: SystemPropertiesNativeBridge = SystemPropertiesNativeBridge(),
) {
    private var getpropSnapshot: Map<String, String>? = null

    public fun collectNativeSnapshot(
        propertyNames: Collection<String>,
    ): SystemPropertiesNativeSnapshot {
        return nativeBridge.collectSnapshot(propertyNames)
    }

    /**
     * Reads every property whose name starts with [prefix], using the same getprop snapshot as the
     * multi-source property checks. A full snapshot is required because Android does not expose a
     * public property-enumeration API; an unavailable getprop result is represented by an empty map.
     */
    public fun collectByPrefix(prefix: String): Map<String, String> {
        return getpropSnapshot()
            .filterKeys { it.startsWith(prefix) }
    }

    public fun readProperty(
        property: String,
        category: SystemPropertyCategory,
        cache: MutableMap<String, MultiSourcePropertyRead>,
        nativeSnapshot: SystemPropertiesNativeSnapshot,
    ): MultiSourcePropertyRead {
        return cache.getOrPut(property) {
            val sourceValues = linkedMapOf<SystemPropertySource, String>()
            sourceValues[SystemPropertySource.REFLECTION] = readViaReflection(property)
            sourceValues[SystemPropertySource.GETPROP] = readViaGetprop(property)
            sourceValues[SystemPropertySource.JVM] = readViaJvm(property)
            sourceValues[SystemPropertySource.NATIVE_LIBC] = nativeSnapshot.libcValue(property)

            val preferredSource = preferredSource(sourceValues)
            MultiSourcePropertyRead(
                property = property,
                category = category,
                preferredValue = sourceValues[preferredSource].orEmpty(),
                preferredSource = preferredSource,
                sourceValues = sourceValues,
            )
        }
    }

    private fun preferredSource(
        sourceValues: Map<SystemPropertySource, String>,
    ): SystemPropertySource {
        return listOf(
            SystemPropertySource.REFLECTION,
            SystemPropertySource.GETPROP,
            SystemPropertySource.NATIVE_LIBC,
            SystemPropertySource.JVM,
        ).firstOrNull { sourceValues[it].isNullOrBlank().not() } ?: SystemPropertySource.REFLECTION
    }

    private fun readViaReflection(
        property: String,
    ): String {
        return HiddenSystemProperties.read(property).getOrNull()?.trim().orEmpty()
    }

    private fun readViaGetprop(
        property: String,
    ): String {
        val snapshot = getpropSnapshot()
        return snapshot[property].orEmpty()
    }

    private fun getpropSnapshot(): Map<String, String> {
        return getpropSnapshot ?: readGetpropSnapshot().also { getpropSnapshot = it }
    }

    private fun readViaJvm(
        property: String,
    ): String {
        return runCatching {
            System.getProperty(property)?.trim().orEmpty()
        }.getOrDefault("")
    }

    private fun readGetpropSnapshot(): Map<String, String> {
        var process: Process? = null
        return try {
            process = ProcessBuilder("getprop")
                .redirectErrorStream(true)
                .start()
            val parsed = process.inputStream.bufferedReader().useLines { lines ->
                lines.mapNotNull { parseGetpropLine(it) }
                    .toMap(linkedMapOf())
            }
            if (!process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
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

    private fun parseGetpropLine(
        line: String,
    ): Pair<String, String>? {
        val trimmed = line.trim()
        if (trimmed.isEmpty()) {
            return null
        }

        val bracketMatch = GETPROP_BRACKET_PATTERN.matchEntire(trimmed)
        if (bracketMatch != null) {
            return bracketMatch.groupValues[1] to bracketMatch.groupValues[2]
        }

        if (!trimmed.contains('=')) {
            return null
        }
        return trimmed.substringBefore('=').trim() to trimmed.substringAfter('=').trim()
    }

    private companion object {
        private const val PROCESS_TIMEOUT_SECONDS = 2L
        private val GETPROP_BRACKET_PATTERN = Regex("""^\[(.+?)]\s*:\s*\[(.*)]$""")
    }
}
