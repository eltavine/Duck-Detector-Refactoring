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
        val mountIdsByPoint = linkedMapOf<String, Long>()
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
            if (parsed.mountPoint in ANCHOR_MOUNT_POINTS) {
                mountIdsByPoint[parsed.mountPoint] = parsed.mountId
            }
            val labels = markerLabels(parsed)
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
            mountIdsByPoint = mountIdsByPoint,
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

    private fun markerLabels(entry: ParsedMountInfo): List<String> = buildList {
        when (entry.source.lowercase()) {
            "magisk" -> add("Magisk")
            "ksu", "kernelsu" -> add("KernelSU")
            "zygisk" -> add("Zygisk")
            "apatch" -> add("APatch")
            "magic_mount" -> add("Magic mount")
        }
        for (path in listOf(entry.mountRoot, entry.mountPoint, entry.source)) {
            if (pathIsWithin(path, "/data/adb")) add("data/adb")
            if (pathIsWithin(path, "/adb/modules")) add("ADB modules")
            if (listOf("/.magisk", "/sbin/.magisk", "/dev/.magisk", "/debug_ramdisk/.magisk").any { pathIsWithin(path, it) }) add("Magisk")
            if (pathIsWithin(path, "/.magic_mount")) add("Magic mount")
            if (pathIsWithin(path, "/debug_ramdisk")) add(ZygoteNextMountMarker.DEBUG_RAMDISK_LABEL)
        }
    }.distinct().sorted()

    private fun pathIsWithin(path: String, prefix: String): Boolean =
        path == prefix || path.startsWith("$prefix/")

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
        private val ANCHOR_MOUNT_POINTS = setOf(
            "/",
            "/dev",
            "/proc",
            "/sys",
            "/data",
            "/system",
            "/vendor",
            "/product",
        )
    }
}
