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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import java.io.File
import java.io.IOException

data class RootProcessAuditProbeResult(
    val available: Boolean,
    val checkedCount: Int,
    val deniedCount: Int,
    val findings: List<NativeRootFinding>,
    val detail: String,
) {
    val hitCount: Int
        get() = findings.size
}

internal data class RootProcessSample(
    val pid: Int,
    val name: String,
    val uid: Int?,
    val gid: Int?,
    val statmPages: Long?,
    val cmdline: String = "",
)

class RootProcessAuditProbe {

    fun run(): RootProcessAuditProbeResult {
        val procDir = File(PROC_ROOT)
        val pidDirs =
            procDir.listFiles()?.filter { file -> file.isDirectory && file.name.all(Char::isDigit) }
                ?: return RootProcessAuditProbeResult(
                    available = false,
                    checkedCount = 0,
                    deniedCount = 0,
                    findings = emptyList(),
                    detail = "Could not enumerate $PROC_ROOT.",
                )

        val samples = mutableListOf<RootProcessSample>()
        var deniedCount = 0

        pidDirs.forEach { pidDir ->
            val pid = pidDir.name.toIntOrNull() ?: return@forEach
            val statmText = readText(File(pidDir, "statm"), 256)
            val statusText = readText(File(pidDir, "status"), 4096)
            if (statmText == null || statusText == null) {
                deniedCount += 1
                return@forEach
            }

            samples += RootProcessSample(
                pid = pid,
                name = parseStatusField(statusText, "Name").orEmpty(),
                uid = parseFirstId(statusText, "Uid"),
                gid = parseFirstId(statusText, "Gid"),
                statmPages = statmText.substringBefore(' ').trim().toLongOrNull(),
                cmdline = readText(File(pidDir, "cmdline"), 256)
                    ?.replace('\u0000', ' ')
                    ?.trim()
                    .orEmpty(),
            )
        }

        return evaluate(
            samples = samples,
            deniedCount = deniedCount,
        )
    }

    internal fun evaluate(
        samples: List<RootProcessSample>,
        deniedCount: Int = 0,
    ): RootProcessAuditProbeResult {
        val findings = samples.mapNotNull { sample ->
            toFinding(sample)
        }

        return RootProcessAuditProbeResult(
            available = true,
            checkedCount = samples.count { (it.statmPages ?: 0L) > 0L },
            deniedCount = deniedCount,
            findings = findings,
            detail = "Checked ${samples.count { (it.statmPages ?: 0L) > 0L }} process status/statm pair(s); denied=$deniedCount.",
        )
    }

    internal fun toFinding(sample: RootProcessSample): NativeRootFinding? {
        val pages = sample.statmPages ?: return null
        if (pages == 0L) {
            return null
        }

        val rootUid = sample.uid == ROOT_ID
        val rootGid = sample.gid == ROOT_ID
        if (!rootUid && !rootGid) {
            return null
        }

        val normalizedName = sample.name.trim()
        if (normalizedName in ROOT_PROCESS_ALLOWLIST) {
            return null
        }

        val lowerContext = buildString {
            append(normalizedName.lowercase())
            append(' ')
            append(sample.cmdline.lowercase())
        }
        val suspicious = ROOT_PROCESS_TOKENS.any { token -> lowerContext.contains(token) }

        return NativeRootFinding(
            id = "root_process_${sample.pid}",
            label = if (suspicious) "Root manager process" else "Unexpected root process",
            value = normalizedName.ifBlank { sample.pid.toString() },
            detail = buildString {
                append("PID ")
                append(sample.pid)
                append(" name=")
                append(if (normalizedName.isBlank()) "<unknown>" else normalizedName)
                append(" uid=")
                append(sample.uid ?: -1)
                append(" gid=")
                append(sample.gid ?: -1)
                if (sample.cmdline.isNotBlank()) {
                    append("\ncmdline=")
                    append(sample.cmdline)
                }
            },
            group = NativeRootGroup.PROCESS,
            severity = if (suspicious) {
                NativeRootFindingSeverity.DANGER
            } else {
                NativeRootFindingSeverity.WARNING
            },
            detailMonospace = true,
        )
    }

    private fun readText(file: File, maxChars: Int): String? {
        return try {
            file.inputStream().buffered().use { stream ->
                val buffer = ByteArray(maxChars)
                val count = stream.read(buffer)
                if (count <= 0) {
                    ""
                } else {
                    String(buffer, 0, count).trim()
                }
            }
        } catch (_: IOException) {
            null
        } catch (_: SecurityException) {
            null
        }
    }

    private fun parseStatusField(
        statusText: String,
        key: String,
    ): String? {
        return statusText.lineSequence()
            .firstOrNull { it.startsWith("$key:") }
            ?.substringAfter(':')
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
    }

    private fun parseFirstId(
        statusText: String,
        key: String,
    ): Int? {
        return parseStatusField(statusText, key)
            ?.split(Regex("\\s+"))
            ?.firstOrNull()
            ?.toIntOrNull()
    }

    private companion object {
        private const val PROC_ROOT = "/proc"
        private const val ROOT_ID = 0

        private val ROOT_PROCESS_ALLOWLIST = setOf(
            "debuggerd",
            "debuggerd64",
            "healthd",
            "init",
            "installd",
            "lmkd",
            "netd",
            "servicemanager",
            "ueventd",
            "vold",
            "watchdogd",
            "zygote",
            "zygote64",
        )

        private val ROOT_PROCESS_TOKENS = setOf(
            "ksud",
            "kernelsu",
            "apd",
            "apatch",
            "kpatch",
            "magisk",
            "magiskd",
            " su ",
            "/su",
            "/data/adb",
        )
    }
}
