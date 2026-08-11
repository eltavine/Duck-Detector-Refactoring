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

package com.eltavine.duckdetector.features.virtualization.data.probes

import java.io.File

/**
 * Enumerates the /proc/<pid>/mountinfo view of every process visible from the current one and
 * reports how many distinct mount tables exist across processes.
 *
 * Technique ported from the PrivIsolated project: a clean observer process (an Android isolated
 * helper in the real detector) reads each other process's mountinfo. Root solutions that hide
 * mounts selectively (Magisk DenyList / KernelSU umount) make different processes see different
 * tables, so the number of distinct views exceeds the expected count (1, or 2 when a shared
 * propagation group is present). Direct root tokens in any view are reported separately.
 *
 * This class is intentionally free of Android framework dependencies so it can run inside the
 * isolated helper process and be unit-tested on the JVM.
 */
data class ProcMountViewScanResult(
    val available: Boolean,
    val distinctViewCount: Int,
    val expectedViewCount: Int,
    val scannedPidCount: Int,
    val tokenHit: Boolean,
    val tokenHitDetail: String,
    val detail: String,
) {
    val divergent: Boolean
        get() = available && distinctViewCount != expectedViewCount
}

internal data class ParsedProcMount(
    val mountId: Int,
    val root: String,
    val point: String,
    val type: String,
    val options: String,
    val source: String,
    val superOptions: String,
    val optional: String,
    val peerGroup: Int,
) {
    fun signature(): String {
        return listOf(source, root, point, type, options, superOptions).joinToString(" ")
    }

    companion object {
        fun parse(line: String): ParsedProcMount? {
            val separator = line.indexOf(" - ")
            if (separator < 0) {
                return null
            }
            val left = line.substring(0, separator).trim()
            val right = line.substring(separator + 3).trim()
            val leftParts = left.split(WHITESPACE)
            val rightParts = right.split(WHITESPACE)
            if (leftParts.size < 6 || rightParts.size < 2) {
                return null
            }
            // left: id parent major:minor root point options [optional fields...]
            val mountId = leftParts[0].toIntOrNull() ?: return null
            val optional = if (leftParts.size > 6) {
                leftParts.subList(6, leftParts.size).joinToString(" ")
            } else {
                ""
            }
            return ParsedProcMount(
                mountId = mountId,
                root = leftParts[3],
                point = leftParts[4],
                type = rightParts[0],
                options = leftParts[5],
                source = rightParts[1],
                superOptions = if (rightParts.size > 2) {
                    rightParts.subList(2, rightParts.size).joinToString(" ")
                } else {
                    ""
                },
                optional = optional,
                peerGroup = parsePeerGroup(optional),
            )
        }

        private fun parsePeerGroup(optionalFields: String): Int {
            val colonIndex = optionalFields.indexOf(':')
            if (colonIndex < 0) {
                return 0
            }
            val spaceIndex = optionalFields.indexOf(' ', colonIndex)
                .let { if (it < 0) optionalFields.length else it }
            val groupString = optionalFields.substring(colonIndex + 1, spaceIndex)
            return groupString.toUIntOrNull()?.toInt() ?: 0
        }

        private val WHITESPACE = Regex("\\s+")
    }
}

class ProcMountViewScanner(
    private val procDirectoryProvider: () -> File = { File("/proc") },
    private val mountInfoLineReader: (pid: String) -> List<String> = { pid ->
        readMountInfoLines(File("/proc", pid))
    },
) {

    fun scan(): ProcMountViewScanResult {
        return runCatching {
            val procDirectory = procDirectoryProvider()
            if (!procDirectory.isDirectory) {
                return unavailable("Unable to read ${procDirectory.absolutePath}")
            }
            val pids = procDirectory.listFiles()
                .orEmpty()
                .mapNotNull { it.name.takeIf { name -> name.isNotEmpty() && name.all(Char::isDigit) } }
                .sortedBy { it.toIntOrNull() ?: Int.MAX_VALUE }
            evaluate(pids, mountInfoLineReader)
        }.getOrElse { throwable ->
            unavailable(throwable.message ?: throwable.javaClass.simpleName)
        }
    }

    internal fun evaluate(
        pids: List<String>,
        lineReader: (pid: String) -> List<String>,
    ): ProcMountViewScanResult {
        var expectedViewCount = 1
        val views = linkedSetOf<String>()
        var tokenHit = false
        var tokenHitDetail = ""
        var readablePidCount = 0

        pids.forEach { pid ->
            val mounts = lineReader(pid)
                .mapNotNull { line -> ParsedProcMount.parse(line) }
            if (mounts.isEmpty()) {
                return@forEach
            }
            readablePidCount += 1
            if (mounts.first().optional.startsWith("shared")) {
                expectedViewCount = 2
            }
            val sorted = mounts.sortedWith(
                compareBy<ParsedProcMount> { it.peerGroup.toUInt() }
                    .thenBy { it.point }
                    .thenBy { it.mountId.toUInt() }
            )

            val builder = StringBuilder()
            sorted.forEach { mount ->
                val signature = mount.signature()
                if (!tokenHit && ROOT_TOKEN_SEQUENCES.any { signature.contains(it) }) {
                    tokenHit = true
                    tokenHitDetail = signature
                }
                builder.append(signature).append('\n')
            }
            views += builder.toString()
        }

        if (readablePidCount == 0) {
            return ProcMountViewScanResult(
                available = false,
                distinctViewCount = 0,
                expectedViewCount = expectedViewCount,
                scannedPidCount = pids.size,
                tokenHit = false,
                tokenHitDetail = "",
                detail = buildString {
                    append("Scanned ")
                    append(pids.size)
                    append(" pid(s) but no process mount table was readable; cross-process mount view comparison is unavailable.")
                },
            )
        }

        return ProcMountViewScanResult(
            available = true,
            distinctViewCount = views.size,
            expectedViewCount = expectedViewCount,
            scannedPidCount = pids.size,
            tokenHit = tokenHit,
            tokenHitDetail = tokenHitDetail,
            detail = buildString {
                append("Scanned ")
                append(pids.size)
                append(" pid(s), ")
                append(readablePidCount)
                append(" readable mount table(s), ")
                append(views.size)
                append(" distinct view(s), expected ")
                append(expectedViewCount)
                append('.')
                if (tokenHit) {
                    append("\nDirect root token: ")
                    append(tokenHitDetail)
                }
            },
        )
    }

    private fun unavailable(reason: String): ProcMountViewScanResult {
        return ProcMountViewScanResult(
            available = false,
            distinctViewCount = 0,
            expectedViewCount = 1,
            scannedPidCount = 0,
            tokenHit = false,
            tokenHitDetail = "",
            detail = reason,
        )
    }

    private companion object {
        val ROOT_TOKEN_SEQUENCES = listOf("magisk", "KSU", "/adb/")

        fun readMountInfoLines(directory: File): List<String> {
            val mountInfo = File(directory, "mountinfo")
            return runCatching {
                mountInfo.bufferedReader(Charsets.UTF_8).use { reader ->
                    reader.readLines()
                }
            }.getOrDefault(emptyList())
        }
    }
}
