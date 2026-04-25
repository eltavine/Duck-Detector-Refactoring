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

package com.eltavine.duckdetector.features.su.data.repository

import com.eltavine.duckdetector.features.su.data.native.SuNativeBridge
import com.eltavine.duckdetector.features.su.domain.SuDaemonFinding
import com.eltavine.duckdetector.features.su.domain.SuMethodOutcome
import com.eltavine.duckdetector.features.su.domain.SuMethodResult
import com.eltavine.duckdetector.features.su.domain.SuReport
import com.eltavine.duckdetector.features.su.domain.SuStage
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class SuRepository(
    private val nativeBridge: SuNativeBridge = SuNativeBridge(),
) {

    suspend fun scan(): SuReport = withContext(Dispatchers.IO) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                SuReport.failed(throwable.message ?: "SU scan failed.")
            }
    }

    private fun scanInternal(): SuReport {
        val foundSuBinaries = linkedSetOf<String>()
        val foundDaemons = linkedMapOf<String, String>()

        SU_PATHS.forEach { path ->
            if (File(path).exists()) {
                foundSuBinaries += path
            }
        }

        DAEMON_PATHS.forEach { (path, name) ->
            if (File(path).exists()) {
                foundDaemons[path] = name
            }
        }

        val pathEnv = System.getenv("PATH")
        pathEnv?.split(File.pathSeparator)
            ?.filter { it.isNotBlank() }
            ?.forEach { pathDir ->
                val suFile = File(pathDir, "su")
                if (suFile.exists()) {
                    foundSuBinaries += suFile.absolutePath
                }
            }

        checkSuExecutable()?.let { path ->
            foundSuBinaries += path
        }

        val nativeSnapshot = nativeBridge.collectSnapshot()
        val selfContext = nativeSnapshot.selfContext.ifBlank { readSelfContextFallback() }
        val selfContextAbnormal = nativeSnapshot.selfContextAbnormal ||
                isAbnormalContext(selfContext)

        val methods = buildMethods(
            foundSuBinaries = foundSuBinaries.toList(),
            foundDaemons = foundDaemons,
            selfContext = selfContext,
            selfContextAbnormal = selfContextAbnormal,
            suspiciousProcesses = nativeSnapshot.suspiciousProcesses,
            nativeAvailable = nativeSnapshot.available,
            checkedProcessCount = nativeSnapshot.checkedProcesses,
            deniedProcessCount = nativeSnapshot.deniedProcesses,
        )

        return SuReport(
            stage = SuStage.READY,
            suBinaries = foundSuBinaries.toList(),
            daemons = foundDaemons.map { (path, name) ->
                SuDaemonFinding(name = name, path = path)
            },
            selfContext = selfContext,
            selfContextAbnormal = selfContextAbnormal,
            suspiciousProcesses = nativeSnapshot.suspiciousProcesses,
            nativeAvailable = nativeSnapshot.available,
            checkedSuPathCount = SU_PATHS.size,
            checkedDaemonPathCount = DAEMON_PATHS.size,
            checkedProcessCount = nativeSnapshot.checkedProcesses,
            deniedProcessCount = nativeSnapshot.deniedProcesses,
            methods = methods,
        )
    }

    private fun buildMethods(
        foundSuBinaries: List<String>,
        foundDaemons: Map<String, String>,
        selfContext: String,
        selfContextAbnormal: Boolean,
        suspiciousProcesses: List<String>,
        nativeAvailable: Boolean,
        checkedProcessCount: Int,
        deniedProcessCount: Int,
    ): List<SuMethodResult> {
        val nativeDetected = selfContextAbnormal || suspiciousProcesses.isNotEmpty()
        val nativeDetail = buildString {
            if (selfContext.isNotBlank()) {
                appendLine("Self: $selfContext")
            }
            if (nativeAvailable) {
                appendLine("Checked: $checkedProcessCount")
                appendLine("Denied: $deniedProcessCount")
                appendLine("Denied reads are supporting visibility evidence only.")
            }
            suspiciousProcesses.forEach { process ->
                appendLine(process)
            }
        }.trim().ifBlank { null }

        return listOf(
            SuMethodResult(
                label = "daemonScan",
                summary = foundDaemons.values.toSet().takeIf { it.isNotEmpty() }?.joinToString("/")
                    ?: "Clean",
                outcome = if (foundDaemons.isNotEmpty()) SuMethodOutcome.DETECTED else SuMethodOutcome.CLEAN,
                detail = foundDaemons.keys.takeIf { it.isNotEmpty() }?.joinToString(),
            ),
            SuMethodResult(
                label = "fileScan",
                summary = if (foundSuBinaries.isNotEmpty()) "SU found" else "Clean",
                outcome = if (foundSuBinaries.isNotEmpty()) SuMethodOutcome.DETECTED else SuMethodOutcome.CLEAN,
                detail = foundSuBinaries.takeIf { it.isNotEmpty() }?.joinToString(),
            ),
            SuMethodResult(
                label = "nativeSyscall",
                summary = when {
                    nativeDetected && nativeAvailable -> "Root context"
                    nativeDetected -> "Fallback abnormal"
                    !nativeAvailable && selfContext.isNotBlank() -> "Fallback context"
                    !nativeAvailable -> "Unavailable"
                    else -> "Normal"
                },
                outcome = when {
                    nativeDetected -> SuMethodOutcome.DETECTED
                    !nativeAvailable -> SuMethodOutcome.SUPPORT
                    else -> SuMethodOutcome.CLEAN
                },
                detail = nativeDetail,
            ),
            SuMethodResult(
                label = "nativeLibrary",
                summary = if (nativeAvailable) "Loaded" else "Unavailable",
                outcome = if (nativeAvailable) SuMethodOutcome.CLEAN else SuMethodOutcome.SUPPORT,
            ),
        )
    }

    private fun checkSuExecutable(): String? {
        var process: Process? = null
        return try {
            process = ProcessBuilder("which", "su")
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().use { it.readText().trim() }
            val completed = process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            if (!completed) {
                process.destroyForcibly()
                null
            } else if (process.exitValue() == 0 && output.isNotBlank()) {
                output.lineSequence().firstOrNull()?.trim()?.takeIf { it.isNotEmpty() }
                    ?: "su (executable in PATH)"
            } else {
                null
            }
        } catch (_: Exception) {
            null
        } finally {
            process?.destroy()
        }
    }

    private fun readSelfContextFallback(): String {
        return try {
            val file = File(PROC_ATTR_PATH)
            if (file.exists() && file.canRead()) {
                file.readText().trim().replace("\u0000", "")
            } else {
                ""
            }
        } catch (_: Exception) {
            ""
        }
    }

    private fun isAbnormalContext(context: String): Boolean {
        if (context.isBlank()) {
            return false
        }
        val lower = context.lowercase()
        if (SUSPICIOUS_CONTEXT_TOKENS.any { token -> lower.contains(token) }) {
            return true
        }
        return NORMAL_CONTEXT_TOKENS.none { token -> lower.contains(token) }
    }

    companion object {
        private const val PROCESS_TIMEOUT_SECONDS = 5L
        private const val PROC_ATTR_PATH = "/proc/self/attr/current"

        private val SU_PATHS = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/su",
            "/system/bin/.ext/.su",
            "/system/usr/we-need-root/su-backup",
            "/system/xbin/mu",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su",
            "/su/bin/su",
            "/magisk/.core/bin/su",
            "/apex/com.android.runtime/bin/su",
            "/system/bin/failsafe/su",
            "/system/sd/xbin/su",
            "/data/adb/su",
            "/data/adb/ksu/bin/su",
            "/data/adb/ap/bin/su",
            "/data/adb/magisk/su",
            "/data/adb/magisk/.magisk/su",
        )

        private val DAEMON_PATHS = linkedMapOf(
            "/data/adb/ksud" to "KernelSU",
            "/data/adb/ksu/ksud" to "KernelSU",
            "/data/adb/magiskd" to "Magisk",
            "/data/adb/magisk/magiskd" to "Magisk",
            "/data/adb/apd" to "APatch",
            "/data/adb/ap/apd" to "APatch",
        )

        private val SUSPICIOUS_CONTEXT_TOKENS = listOf(
            "magisk",
            "apatch",
            "kernelsu",
            ":su:",
            "permissive",
            "unconfined",
        )

        private val NORMAL_CONTEXT_TOKENS = listOf(
            "untrusted_app",
            "platform_app",
            "system_app",
            "priv_app",
        )
    }
}
