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

package com.eltavine.duckdetector.features.nativeroot.data.service

data class ThroneHuntCarrierState(
    val watchInstalled: Boolean = false,
    val watchDescriptor: Int = -1,
    val packageDirectory: String = "",
    val failureReason: String? = null,
    val notes: List<String> = emptyList(),
    val directoryOpenCount: Int = 0,
    val directoryAccessCount: Int = 0,
) {
    // A denied watch never counts as coverage: the carrier reports it as a failure reason whose
    // text carries "denied", and the round must surface that instead of a clean zero.
    val watchDenied: Boolean
        get() = failureReason?.contains("denied", ignoreCase = true) == true
}

// The preload carrier hands the isolated child a plain string because the watch descriptor is
// inherited through fork, not through the Binder transaction. Keeping the encoding trivial means
// the isolated child can rebuild the state with no framework dependency.
object ThroneHuntCarrierPayloadCodec {

    fun encode(state: ThroneHuntCarrierState): String {
        return buildString {
            append("WATCH_INSTALLED=")
            append(if (state.watchInstalled) '1' else '0')
            append('\n')
            append("WATCH_DESCRIPTOR=")
            append(state.watchDescriptor)
            append('\n')
            append("WATCH_PACKAGE_DIR=")
            append(escape(state.packageDirectory))
            append('\n')
            if (state.failureReason != null) {
                append("FAILURE_REASON=")
                append(escape(state.failureReason))
                append('\n')
            }
            append("EVENT_DIRECTORY_OPEN=")
            append(state.directoryOpenCount)
            append('\n')
            append("EVENT_DIRECTORY_ACCESS=")
            append(state.directoryAccessCount)
            append('\n')
            state.notes.forEach { note ->
                append("NOTE=")
                append(escape(note))
                append('\n')
            }
        }
    }

    fun decode(raw: String): ThroneHuntCarrierState {
        if (raw.isBlank()) {
            return ThroneHuntCarrierState()
        }
        var state = ThroneHuntCarrierState()
        val notes = mutableListOf<String>()
        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when {
                    line.startsWith("NOTE=") -> notes += line.removePrefix("NOTE=").unescape()

                    line.contains('=') -> {
                        val key = line.substringBefore('=')
                        val value = line.substringAfter('=')
                        state = when (key) {
                            "WATCH_INSTALLED" -> state.copy(
                                watchInstalled = value == "1" || value.equals("true", true)
                            )

                            "WATCH_DESCRIPTOR" -> state.copy(
                                watchDescriptor = value.toIntOrNull() ?: state.watchDescriptor
                            )

                            "WATCH_PACKAGE_DIR" -> state.copy(packageDirectory = value.unescape())
                            "FAILURE_REASON" -> state.copy(failureReason = value.unescape())

                            "EVENT_DIRECTORY_OPEN" -> state.copy(
                                directoryOpenCount = value.toIntOrNull() ?: state.directoryOpenCount
                            )

                            "EVENT_DIRECTORY_ACCESS" -> state.copy(
                                directoryAccessCount = value.toIntOrNull()
                                    ?: state.directoryAccessCount
                            )

                            else -> state
                        }
                    }
                }
            }
        return state.copy(notes = notes)
    }

    private fun escape(value: String): String {
        return buildString(value.length) {
            value.forEach { ch ->
                when (ch) {
                    '\\' -> append("\\\\")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(ch)
                }
            }
        }
    }

    private fun String.unescape(): String {
        return buildString(length) {
            var index = 0
            while (index < this@unescape.length) {
                val current = this@unescape[index]
                if (current == '\\' && index + 1 < this@unescape.length) {
                    when (this@unescape[index + 1]) {
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
}
