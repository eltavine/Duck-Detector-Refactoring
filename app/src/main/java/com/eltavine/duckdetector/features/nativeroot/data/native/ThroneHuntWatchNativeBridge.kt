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

package com.eltavine.duckdetector.features.nativeroot.data.native

open class ThroneHuntWatchNativeBridge {

    fun installWatch(packageDirectory: String): ThroneHuntWatchSnapshot {
        return runCatching { parseWatch(nativeInstallWatch(packageDirectory)) }
            .getOrDefault(ThroneHuntWatchSnapshot(packageDirectory = packageDirectory))
    }

    open fun drainWatch(watchDescriptor: Int): ThroneHuntEventSummary {
        return runCatching { parseEvents(nativeDrainWatch(watchDescriptor)) }
            .getOrDefault(ThroneHuntEventSummary())
    }

    fun resetWatch(watchDescriptor: Int) {
        runCatching { nativeResetWatch(watchDescriptor) }
    }

    internal fun parseWatch(raw: String): ThroneHuntWatchSnapshot {
        var snapshot = ThroneHuntWatchSnapshot()
        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && it.contains('=') }
            .forEach { line ->
                val key = line.substringBefore('=')
                val value = line.substringAfter('=')
                snapshot = when (key) {
                    "WATCH_INSTALLED" -> snapshot.copy(watchInstalled = value.asBool())
                    "WATCH_DESCRIPTOR" -> snapshot.copy(
                        watchDescriptor = value.toIntOrNull() ?: snapshot.watchDescriptor
                    )

                    "WATCH_ERRNO" -> snapshot.copy(
                        errorNumber = value.toIntOrNull() ?: snapshot.errorNumber
                    )

                    "WATCH_PACKAGE_DIR" -> snapshot.copy(
                        packageDirectory = value.decodeValue()
                    )

                    "WATCH_DETAIL" -> snapshot.copy(detail = value.decodeValue())
                    else -> snapshot
                }
            }
        return snapshot
    }

    internal fun parseEvents(raw: String): ThroneHuntEventSummary {
        var summary = ThroneHuntEventSummary()
        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && it.contains('=') }
            .forEach { line ->
                val key = line.substringBefore('=')
                val value = line.substringAfter('=')
                summary = when (key) {
                    "EVENT_DIRECTORY_OPEN" -> summary.copy(
                        directoryOpenCount = value.toIntOrNull() ?: summary.directoryOpenCount
                    )

                    "EVENT_DIRECTORY_ACCESS" -> summary.copy(
                        directoryAccessCount = value.toIntOrNull() ?: summary.directoryAccessCount
                    )

                    "EVENT_RAW" -> summary.copy(
                        rawEventCount = value.toIntOrNull() ?: summary.rawEventCount
                    )

                    "EVENT_INVALID" -> summary.copy(
                        invalidCount = value.toIntOrNull() ?: summary.invalidCount
                    )

                    "EVENT_DETAIL" -> summary.copy(detail = value.decodeValue())
                    else -> summary
                }
            }
        return summary
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

    private external fun nativeInstallWatch(packageDirectory: String): String

    private external fun nativeDrainWatch(watchDescriptor: Int): String

    private external fun nativeResetWatch(watchDescriptor: Int)

    companion object {
        private val nativeLoaded = runCatching { System.loadLibrary("duckdetector") }.isSuccess

        @JvmStatic
        val isNativeLibraryLoaded: Boolean
            get() = nativeLoaded
    }
}
