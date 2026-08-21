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

package com.eltavine.duckdetector.features.mount.data.zygotenext

import android.os.Process
import android.system.Os
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths

open class ZygoteNextLocalProbe {

    open fun collect(): ZygoteNextProcessSnapshot {
        return runCatching {
            val lines = File(MOUNTINFO_PATH).bufferedReader().useLines { it.toList() }
            parseMountInfo(
                lines = lines,
                pid = Process.myPid(),
                parentPid = Os.getppid(),
                uid = Process.myUid(),
                namespaceInode = readNamespaceInode(NAMESPACE_PATH),
            )
        }.getOrElse { throwable ->
            ZygoteNextProcessSnapshot(
                available = false,
                errorDetail = throwable.message ?: "Main-process mountinfo could not be read.",
            )
        }
    }

    internal fun parseMountInfo(
        lines: List<String>,
        pid: Int = 1,
        parentPid: Int = 0,
        uid: Int = 0,
        namespaceInode: Long = 0L,
    ): ZygoteNextProcessSnapshot {
        var rootPropagation = ""
        var rootMountId = 0L
        var minimumMountId = 0L
        var maximumMountId = 0L
        var mountCount = 0
        val markers = mutableListOf<ZygoteNextMountMarker>()
        lines.forEach { line ->
            val parsed = parseLine(line) ?: return@forEach
            mountCount += 1
            if (minimumMountId == 0L || parsed.mountId < minimumMountId) {
                minimumMountId = parsed.mountId
            }
            if (parsed.mountId > maximumMountId) maximumMountId = parsed.mountId
            if (parsed.mountPoint == "/") {
                rootMountId = parsed.mountId
                rootPropagation = parsed.optionalFields
                    .filter { it.startsWith("shared:") || it.startsWith("master:") }
                    .joinToString(" ")
            }
            val labels = markerLabels(line)
            if (labels.isNotEmpty()) {
                markers += ZygoteNextMountMarker(
                    labels = labels,
                    mountPoint = parsed.mountPoint,
                    mountRoot = parsed.mountRoot,
                    fileSystemType = parsed.fileSystemType,
                    source = parsed.source,
                    rawLine = line,
                )
            }
        }
        return ZygoteNextProcessSnapshot(
            available = true,
            pid = pid,
            parentPid = parentPid,
            uid = uid,
            mountNamespaceInode = namespaceInode,
            rootPropagation = rootPropagation,
            rootMountId = rootMountId,
            minimumMountId = minimumMountId,
            maximumMountId = maximumMountId,
            mountCount = mountCount,
            markers = markers,
        )
    }

    private fun parseLine(line: String): ParsedMountInfo? {
        val separator = line.indexOf(" - ")
        if (separator < 0) return null
        val before = line.substring(0, separator).split(' ').filter(String::isNotEmpty)
        val after = line.substring(separator + 3).split(' ').filter(String::isNotEmpty)
        if (before.size < 6 || after.size < 2) return null
        val mountId = before[0].toLongOrNull()?.takeIf { it > 0L } ?: return null
        return ParsedMountInfo(
            mountId = mountId,
            mountRoot = before[3],
            mountPoint = before[4],
            optionalFields = before.drop(6),
            fileSystemType = after[0],
            source = after[1],
        )
    }

    private fun markerLabels(line: String): List<String> {
        val normalized = line.lowercase()
        return buildList {
            if (normalized.contains("magisk")) add("Magisk")
            if (normalized.contains("kernelsu") || containsNamedMarker(normalized, "ksu")) {
                add("KernelSU")
            }
            if (normalized.contains("zygisk")) add("Zygisk")
            if (containsNamedMarker(normalized, "zn")) add("ZN")
            if (containsNamedMarker(normalized, "sui")) add("Sui")
            if (containsNamedMarker(normalized, "lsp", requireEnd = false)) add("LSP")
            if (containsPathPrefix(normalized, "/data/adb")) {
                add("data/adb")
            } else if (containsPathPrefix(normalized, "/adb/modules")) {
                add("ADB modules")
            }
            if (normalized.contains("/debug_ramdisk")) {
                add(ZygoteNextMountMarker.DEBUG_RAMDISK_LABEL)
            }
        }
    }

    private fun containsNamedMarker(
        text: String,
        marker: String,
        requireEnd: Boolean = true,
    ): Boolean {
        var start = text.indexOf(marker)
        while (start >= 0) {
            val end = start + marker.length
            val startBoundary = start == 0 || !text[start - 1].isLetterOrDigit()
            val endBoundary = !requireEnd || end == text.length || !text[end].isLetterOrDigit()
            if (startBoundary && endBoundary) return true
            start = text.indexOf(marker, start + 1)
        }
        return false
    }

    private fun containsPathPrefix(text: String, path: String): Boolean {
        var start = text.indexOf(path)
        while (start >= 0) {
            val end = start + path.length
            val endBoundary = end == text.length || text[end] == '/' ||
                text[end].isWhitespace() || text[end] == ',' || text[end] == ':'
            if (endBoundary) return true
            start = text.indexOf(path, start + 1)
        }
        return false
    }

    private fun readNamespaceInode(path: String): Long {
        return runCatching {
            val target = Files.readSymbolicLink(Paths.get(path)).toString()
            target.substringAfterLast('[').substringBefore(']').toLong()
        }.getOrDefault(0L)
    }

    private data class ParsedMountInfo(
        val mountId: Long,
        val mountRoot: String,
        val mountPoint: String,
        val optionalFields: List<String>,
        val fileSystemType: String,
        val source: String,
    )

    companion object {
        private const val MOUNTINFO_PATH = "/proc/self/mountinfo"
        private const val NAMESPACE_PATH = "/proc/self/ns/mnt"
    }
}
