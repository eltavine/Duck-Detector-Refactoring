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

package com.eltavine.duckdetector.features.selinux.data.native

open class SelinuxNativeAuditBridge {

    open fun collectSnapshot(): SelinuxNativeAuditSnapshot {
        if (!nativeLoaded) {
            return SelinuxNativeAuditSnapshot(
                failureReason = "duckdetector native library unavailable.",
            )
        }
        return runCatching {
            parse(nativeCollectAuditSnapshot())
        }.getOrDefault(SelinuxNativeAuditSnapshot())
    }

    internal fun parse(raw: String): SelinuxNativeAuditSnapshot {
        if (raw.isBlank()) {
            return SelinuxNativeAuditSnapshot()
        }

        var snapshot = SelinuxNativeAuditSnapshot()
        val callbackLines = mutableListOf<String>()

        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when {
                    line.startsWith("LINE=") -> callbackLines += line.removePrefix("LINE=")
                        .decodeValue()

                    line.contains('=') -> {
                        val key = line.substringBefore('=')
                        val value = line.substringAfter('=')
                        snapshot = snapshot.applyEntry(key, value)
                    }
                }
            }

        return snapshot.copy(callbackLines = callbackLines)
    }

    private fun SelinuxNativeAuditSnapshot.applyEntry(
        key: String,
        value: String,
    ): SelinuxNativeAuditSnapshot {
        return when (key) {
            "AVAILABLE" -> copy(available = value.asBool())
            "CALLBACK_INSTALLED" -> copy(callbackInstalled = value.asBool())
            "PROBE_RAN" -> copy(probeRan = value.asBool())
            "DENIAL_OBSERVED" -> copy(denialObserved = value.asBool())
            "ALLOW_OBSERVED" -> copy(allowObserved = value.asBool())
            "PROBE_MARKER" -> copy(probeMarker = value.decodeValue())
            "FAILURE_REASON" -> copy(failureReason = value.decodeValue())
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

    private external fun nativeCollectAuditSnapshot(): String

    companion object {
        private val nativeLoaded = runCatching { System.loadLibrary("duckdetector") }.isSuccess
    }
}
