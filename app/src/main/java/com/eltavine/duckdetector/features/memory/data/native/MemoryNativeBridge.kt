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

package com.eltavine.duckdetector.features.memory.data.native

class MemoryNativeBridge {

    fun collectSnapshot(): MemoryNativeSnapshot {
        return runCatching {
            parse(nativeCollectSnapshot())
        }.getOrDefault(MemoryNativeSnapshot())
    }

    internal fun parse(raw: String): MemoryNativeSnapshot {
        if (raw.isBlank()) {
            return MemoryNativeSnapshot()
        }

        var snapshot = MemoryNativeSnapshot()
        val findings = mutableListOf<MemoryNativeFinding>()
        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when {
                    line.startsWith("FINDING=") -> {
                        val parts = line.removePrefix("FINDING=").split('\t', limit = 5)
                        if (parts.size == 5) {
                            findings += MemoryNativeFinding(
                                section = parts[0],
                                category = parts[1],
                                label = parts[2],
                                severity = parts[3],
                                detail = parts[4].decodeValue(),
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
        return snapshot.copy(findings = findings)
    }

    private fun MemoryNativeSnapshot.applyEntry(
        key: String,
        value: String,
    ): MemoryNativeSnapshot {
        return when (key) {
            "AVAILABLE" -> copy(available = value.asBool())
            "GOT_PLT_HOOK" -> copy(gotPltHook = value.asBool())
            "INLINE_HOOK" -> copy(inlineHook = value.asBool())
            "PROLOGUE_MODIFIED" -> copy(prologueModified = value.asBool())
            "TRAMPOLINE" -> copy(trampoline = value.asBool())
            "SUSPICIOUS_JUMP" -> copy(suspiciousJump = value.asBool())
            "MODIFIED_FUNCTION_COUNT" -> copy(
                modifiedFunctionCount = value.toIntOrNull() ?: modifiedFunctionCount
            )

            "WRITABLE_EXEC" -> copy(writableExec = value.asBool())
            "ANONYMOUS_EXEC" -> copy(anonymousExec = value.asBool())
            "SWAPPED_EXEC" -> copy(swappedExec = value.asBool())
            "SHARED_DIRTY_EXEC" -> copy(sharedDirtyExec = value.asBool())
            "DELETED_SO" -> copy(deletedSo = value.asBool())
            "SUSPICIOUS_MEMFD" -> copy(suspiciousMemfd = value.asBool())
            "EXEC_ASHMEM" -> copy(execAshmem = value.asBool())
            "DEV_ZERO_EXEC" -> copy(devZeroExec = value.asBool())
            "SIGNAL_HANDLER" -> copy(signalHandler = value.asBool())
            "FRIDA_SIGNAL" -> copy(fridaSignal = value.asBool())
            "ANONYMOUS_SIGNAL" -> copy(anonymousSignal = value.asBool())
            "VDSO_REMAPPED" -> copy(vdsoRemapped = value.asBool())
            "VDSO_UNUSUAL_BASE" -> copy(vdsoUnusualBase = value.asBool())
            "DELETED_LIBRARY" -> copy(deletedLibrary = value.asBool())
            "HIDDEN_MODULE" -> copy(hiddenModule = value.asBool())
            "MAPS_ONLY_MODULE" -> copy(mapsOnlyModule = value.asBool())
            "CRITICAL_COUNT" -> copy(criticalCount = value.toIntOrNull() ?: criticalCount)
            "HIGH_COUNT" -> copy(highCount = value.toIntOrNull() ?: highCount)
            "MEDIUM_COUNT" -> copy(mediumCount = value.toIntOrNull() ?: mediumCount)
            "LOW_COUNT" -> copy(lowCount = value.toIntOrNull() ?: lowCount)
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
