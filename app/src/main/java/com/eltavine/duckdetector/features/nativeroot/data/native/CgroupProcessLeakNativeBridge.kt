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

data class CgroupProcessLeakNativePath(
    val path: String,
    val uid: Int,
    val accessible: Boolean,
    val pidCount: Int,
)

data class CgroupProcessLeakNativeEntry(
    val uidPath: String,
    val cgroupUid: Int,
    val pid: Int,
    val procUid: Int?,
    val startTimeTicks: Long? = null,
    val killErrno: Int? = null,
    val sid: Int? = null,
    val sidErrno: Int? = null,
    val pgid: Int? = null,
    val pgidErrno: Int? = null,
    val schedulerPolicy: Int? = null,
    val schedulerErrno: Int? = null,
    val pidfdErrno: Int? = null,
    val procContext: String = "",
    val comm: String,
    val cmdline: String,
)

data class CgroupProcessLeakNativeSnapshot(
    val available: Boolean = false,
    val pathCheckCount: Int = 0,
    val accessiblePathCount: Int = 0,
    val processCount: Int = 0,
    val procDeniedCount: Int = 0,
    val paths: List<CgroupProcessLeakNativePath> = emptyList(),
    val entries: List<CgroupProcessLeakNativeEntry> = emptyList(),
)

class CgroupProcessLeakNativeBridge {

    fun collectSnapshot(): CgroupProcessLeakNativeSnapshot {
        return runCatching {
            parse(nativeCollectSnapshot())
        }.getOrDefault(CgroupProcessLeakNativeSnapshot())
    }

    internal fun parse(raw: String): CgroupProcessLeakNativeSnapshot {
        if (raw.isBlank()) {
            return CgroupProcessLeakNativeSnapshot()
        }

        var available = false
        var pathCheckCount = 0
        var accessiblePathCount = 0
        var processCount = 0
        var procDeniedCount = 0
        val paths = mutableListOf<CgroupProcessLeakNativePath>()
        val entries = mutableListOf<CgroupProcessLeakNativeEntry>()

        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when {
                    line.startsWith("PATH=") -> {
                        val parts = line.removePrefix("PATH=").split('\t', limit = 4)
                        val uid = parts.getOrNull(1)?.toIntOrNull()
                        val accessible = parts.getOrNull(2)
                        val pidCount = parts.getOrNull(3)?.toIntOrNull()
                        if (parts.size == 4 && uid != null && accessible != null && pidCount != null) {
                            paths += CgroupProcessLeakNativePath(
                                path = parts[0].decodeValue(),
                                uid = uid,
                                accessible = accessible == "1",
                                pidCount = pidCount,
                            )
                        }
                    }

                    line.startsWith("ENTRY=") -> {
                        val rawEntry = line.removePrefix("ENTRY=")
                        val expandedParts = rawEntry.split('\t', limit = 16)
                        val expandedCgroupUid = expandedParts.getOrNull(1)?.toIntOrNull()
                        val expandedPid = expandedParts.getOrNull(2)?.toIntOrNull()
                        val expandedProcUid = expandedParts.getOrNull(3)?.toIntOrNull()
                        if (expandedParts.size == 16 &&
                            expandedCgroupUid != null &&
                            expandedPid != null
                        ) {
                            entries += CgroupProcessLeakNativeEntry(
                                uidPath = expandedParts[0].decodeValue(),
                                cgroupUid = expandedCgroupUid,
                                pid = expandedPid,
                                procUid = expandedProcUid?.takeIf { it >= 0 },
                                startTimeTicks = expandedParts.getOrNull(4)?.toLongOrNull()
                                    ?.takeIf { it >= 0L },
                                killErrno = expandedParts.getOrNull(5)?.toIntOrNull()
                                    ?.takeIf { it >= 0 },
                                sid = expandedParts.getOrNull(6)?.toIntOrNull()
                                    ?.takeIf { it >= 0 },
                                sidErrno = expandedParts.getOrNull(7)?.toIntOrNull()
                                    ?.takeIf { it >= 0 },
                                pgid = expandedParts.getOrNull(8)?.toIntOrNull()
                                    ?.takeIf { it >= 0 },
                                pgidErrno = expandedParts.getOrNull(9)?.toIntOrNull()
                                    ?.takeIf { it >= 0 },
                                schedulerPolicy = expandedParts.getOrNull(10)?.toIntOrNull()
                                    ?.takeIf { it >= 0 },
                                schedulerErrno = expandedParts.getOrNull(11)?.toIntOrNull()
                                    ?.takeIf { it >= 0 },
                                pidfdErrno = expandedParts.getOrNull(12)?.toIntOrNull()
                                    ?.takeIf { it >= 0 },
                                procContext = expandedParts.getOrNull(13)?.decodeValue().orEmpty(),
                                comm = expandedParts.getOrNull(14)?.decodeValue()
                                    .orEmpty(),
                                cmdline = expandedParts.getOrNull(15)
                                    ?.decodeValue()
                                    .orEmpty(),
                            )
                        } else {
                            val legacyParts = rawEntry.split('\t', limit = 7)
                            val legacyCgroupUid = legacyParts.getOrNull(1)?.toIntOrNull()
                            val legacyPid = legacyParts.getOrNull(2)?.toIntOrNull()
                            val legacyProcUid = legacyParts.getOrNull(3)?.toIntOrNull()
                            if ((legacyParts.size == 6 || legacyParts.size == 7) &&
                                legacyCgroupUid != null &&
                                legacyPid != null
                            ) {
                                entries += CgroupProcessLeakNativeEntry(
                                    uidPath = legacyParts[0].decodeValue(),
                                    cgroupUid = legacyCgroupUid,
                                    pid = legacyPid,
                                    procUid = legacyProcUid?.takeIf { it >= 0 },
                                    procContext = legacyParts.getOrNull(4)?.decodeValue().orEmpty(),
                                    comm = legacyParts.getOrNull(if (legacyParts.size == 7) 5 else 4)
                                        ?.decodeValue()
                                        .orEmpty(),
                                    cmdline = legacyParts.getOrNull(if (legacyParts.size == 7) 6 else 5)
                                        ?.decodeValue()
                                        .orEmpty(),
                                )
                            }
                        }
                    }

                    line.contains('=') -> {
                        val key = line.substringBefore('=')
                        val value = line.substringAfter('=')
                        when (key) {
                            "AVAILABLE" -> available = value == "1"
                            "PATH_CHECKS" -> pathCheckCount = value.toIntOrNull() ?: pathCheckCount
                            "PATH_ACCESSIBLE" -> accessiblePathCount =
                                value.toIntOrNull() ?: accessiblePathCount

                            "PROCESS_COUNT" -> processCount = value.toIntOrNull() ?: processCount
                            "PROC_DENIED" -> procDeniedCount =
                                value.toIntOrNull() ?: procDeniedCount
                        }
                    }
                }
            }

        return CgroupProcessLeakNativeSnapshot(
            available = available,
            pathCheckCount = pathCheckCount,
            accessiblePathCount = accessiblePathCount,
            processCount = processCount,
            procDeniedCount = procDeniedCount,
            paths = paths,
            entries = entries,
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

                        '0' -> {
                            append('\u0000')
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
