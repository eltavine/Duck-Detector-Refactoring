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

package com.eltavine.duckdetector.features.lsposed.data.probes

import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import java.util.concurrent.TimeUnit

data class LSPosedLogcatProbeResult(
    val signals: List<LSPosedSignal>,
    val available: Boolean,
    val failureReason: String? = null,
) {
    val hitCount: Int
        get() = signals.size

    val dangerHitCount: Int
        get() = signals.count { it.severity == LSPosedSignalSeverity.DANGER }

    val warningHitCount: Int
        get() = signals.count { it.severity == LSPosedSignalSeverity.WARNING }
}

fun interface LSPosedLogcatCommandRunner {
    fun run(
        command: List<String>,
        timeoutMs: Long,
    ): LSPosedLogcatCommandOutput
}

data class LSPosedLogcatCommandOutput(
    val output: String = "",
    val timedOut: Boolean = false,
    val errorMessage: String? = null,
)

class LSPosedLogcatProbe(
    private val commandRunner: LSPosedLogcatCommandRunner = LSPosedLogcatCommandRunner(::runCommand),
) {

    fun run(): LSPosedLogcatProbeResult {
        val outputs = COMMANDS.associate { spec ->
            spec.id to commandRunner.run(spec.command, PROCESS_TIMEOUT_MS)
        }
        return evaluate(outputs)
    }

    internal fun evaluate(
        outputs: Map<String, LSPosedLogcatCommandOutput>,
    ): LSPosedLogcatProbeResult {
        val signals = mutableListOf<LSPosedSignal>()
        val emittedIds = linkedSetOf<String>()
        var available = false

        outputs.forEach { (id, output) ->
            if (output.timedOut) {
                return@forEach
            }

            val failureText = listOfNotNull(
                output.errorMessage,
                output.output.takeIf { it.isNotBlank() },
            ).joinToString(separator = "\n")
            if (failureText.isLogAccessDenied()) {
                return@forEach
            }

            if (output.errorMessage == null || output.output.isNotBlank()) {
                available = true
            }

            when {
                id == PROCESS_COMMAND_ID -> signals += parseProcessOutput(output.output, emittedIds)
                id.startsWith(TAG_COMMAND_PREFIX) -> signals += parseTagOutput(
                    id,
                    output.output,
                    emittedIds
                )

                else -> signals += parseOverview(output.output, emittedIds)
            }
        }

        return LSPosedLogcatProbeResult(
            signals = signals.distinctBy { signal -> signal.id to signal.detail },
            available = available,
            failureReason = if (available) null else "Recent log buffers are not readable from the current app context.",
        )
    }

    private fun parseOverview(
        output: String,
        emittedIds: MutableSet<String>,
    ): List<LSPosedSignal> {
        if (output.isBlank()) {
            return emptyList()
        }

        val signals = mutableListOf<LSPosedSignal>()
        meaningfulLines(output).forEach { line ->
            val tag = Regex("""^[VDIWEF]/([^(]+)\(""")
                .find(line)
                ?.groupValues
                ?.getOrNull(1)
                ?.trim()

            tag?.let { currentTag ->
                LSPosedProbeSupport.logcatTags.firstOrNull { knownTag ->
                    currentTag.equals(knownTag, ignoreCase = true) ||
                            currentTag.contains(knownTag, ignoreCase = true)
                }?.let { matchedTag ->
                    val signalId = "logcat_tag_${matchedTag.toSignalIdSegment()}"
                    if (emittedIds.add(signalId)) {
                        signals += dangerSignal(
                            id = signalId,
                            label = "Logcat tag",
                            value = currentTag,
                            detail = line.trimToPreview(),
                        )
                    }
                }

                LSPosedProbeSupport.logcatTagPrefixes.firstOrNull { prefix ->
                    currentTag.startsWith(prefix, ignoreCase = true)
                }?.let { matchedPrefix ->
                    val signalId =
                        "logcat_prefix_${matchedPrefix.toSignalIdSegment()}_${currentTag.toSignalIdSegment()}"
                    if (emittedIds.add(signalId)) {
                        signals += dangerSignal(
                            id = signalId,
                            label = "Logcat tag prefix",
                            value = currentTag,
                            detail = line.trimToPreview(),
                        )
                    }
                }
            }

            LSPosedProbeSupport.logcatPatterns.forEach { pattern ->
                if (!line.matchesPattern(pattern)) {
                    return@forEach
                }

                val signalId = "logcat_pattern_${pattern.toSignalIdSegment()}"
                if (emittedIds.add(signalId)) {
                    val strong = pattern.startsWith("!!")
                    signals += LSPosedSignal(
                        id = signalId,
                        label = "Logcat pattern",
                        value = pattern,
                        group = LSPosedSignalGroup.RUNTIME,
                        severity = if (strong) LSPosedSignalSeverity.DANGER else LSPosedSignalSeverity.WARNING,
                        detail = line.trimToPreview(),
                        detailMonospace = true,
                    )
                }
            }

            val lowerLine = line.lowercase()
            if (
                lowerLine.contains("lsposed") ||
                lowerLine.contains("lspd") ||
                (lowerLine.contains("xposed") && lowerLine.contains("bridge"))
            ) {
                val signalId = "logcat_direct_${line.take(48).toSignalIdSegment()}"
                if (emittedIds.add(signalId)) {
                    signals += dangerSignal(
                        id = signalId,
                        label = "Logcat direct hit",
                        value = "Direct",
                        detail = line.trimToPreview(),
                    )
                }
            }
        }

        return signals
    }

    private fun parseTagOutput(
        id: String,
        output: String,
        emittedIds: MutableSet<String>,
    ): List<LSPosedSignal> {
        val lines = meaningfulLines(output)
        if (lines.isEmpty()) {
            return emptyList()
        }

        val tag = id.removePrefix(TAG_COMMAND_PREFIX)
        val signalId = "logcat_filter_${tag.toSignalIdSegment()}"
        if (!emittedIds.add(signalId)) {
            return emptyList()
        }

        return listOf(
            dangerSignal(
                id = signalId,
                label = "Logcat tag filter",
                value = "${lines.size} line(s)",
                detail = buildString {
                    appendLine("Tag: $tag")
                    lines.take(6).forEach { line -> appendLine(line.trimToPreview()) }
                }.trim(),
            ),
        )
    }

    private fun parseProcessOutput(
        output: String,
        emittedIds: MutableSet<String>,
    ): List<LSPosedSignal> {
        val line = meaningfulLines(output).firstOrNull { entry ->
            entry.contains("org.lsposed.daemon", ignoreCase = true) ||
                    entry.contains("lsposed daemon", ignoreCase = true)
        } ?: return emptyList()

        val signalId = "logcat_process_lsposed_daemon"
        if (!emittedIds.add(signalId)) {
            return emptyList()
        }

        return listOf(
            dangerSignal(
                id = signalId,
                label = "Logcat process",
                value = "org.lsposed.daemon",
                detail = line.trimToPreview(),
            ),
        )
    }

    private fun meaningfulLines(
        output: String,
    ): List<String> {
        return output.lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .filterNot { it.startsWith("---------") }
            .filterNot(::shouldExcludeLine)
            .toList()
    }

    private fun shouldExcludeLine(
        line: String,
    ): Boolean {
        val lower = line.lowercase()
        return LSPosedProbeSupport.runtimeExcludePatterns.any { token -> lower.contains(token) }
    }

    private fun String.matchesPattern(
        pattern: String,
    ): Boolean {
        val lowerLine = lowercase()
        val lowerPattern = pattern.lowercase()
        if (!lowerLine.contains(lowerPattern)) {
            return false
        }

        val isControlMessage = pattern.startsWith("!!")
        val isLsposedSpecific = pattern.contains("SystemClassLoader") ||
                pattern.contains("InMemoryDexClassLoader") ||
                pattern.contains("ObfuscationManager") ||
                pattern.contains("startBootstrapHook") ||
                pattern.contains("LoadedApk#")

        return isControlMessage ||
                isLsposedSpecific ||
                lowerLine.contains("xposed") ||
                lowerLine.contains("lsposed") ||
                lowerLine.contains("module")
    }

    private fun dangerSignal(
        id: String,
        label: String,
        value: String,
        detail: String,
    ): LSPosedSignal {
        return LSPosedSignal(
            id = id,
            label = label,
            value = value,
            group = LSPosedSignalGroup.RUNTIME,
            severity = LSPosedSignalSeverity.DANGER,
            detail = detail,
            detailMonospace = true,
        )
    }

    private fun String?.isLogAccessDenied(): Boolean {
        return this?.contains("Permission denied", ignoreCase = true) == true ||
                this?.contains("EACCES", ignoreCase = true) == true ||
                this?.contains("not allowed to read logs", ignoreCase = true) == true ||
                this?.contains("READ_LOGS", ignoreCase = true) == true
    }

    private data class LogcatCommandSpec(
        val id: String,
        val command: List<String>,
    )

    private companion object {
        private const val PROCESS_TIMEOUT_MS = 3500L
        private const val OVERVIEW_COMMAND_ID = "overview"
        private const val PROCESS_COMMAND_ID = "process"
        private const val TAG_COMMAND_PREFIX = "tag:"

        private val COMMANDS = buildList {
            add(
                LogcatCommandSpec(
                    id = OVERVIEW_COMMAND_ID,
                    command = listOf("logcat", "-d", "-v", "brief", "-t", "1000"),
                ),
            )
            LSPosedProbeSupport.logcatTags
                .filter { tag ->
                    tag == "LSPosed" || tag == "LSPosed-Bridge" || tag == "LSPosedService"
                }
                .forEach { tag ->
                    add(
                        LogcatCommandSpec(
                            id = "$TAG_COMMAND_PREFIX$tag",
                            command = listOf(
                                "logcat",
                                "-d",
                                "-v",
                                "brief",
                                "-s",
                                "$tag:*",
                                "-t",
                                "50"
                            ),
                        ),
                    )
                }
            add(
                LogcatCommandSpec(
                    id = PROCESS_COMMAND_ID,
                    command = listOf("logcat", "-d", "-v", "process", "-t", "500"),
                ),
            )
        }

        private fun runCommand(
            command: List<String>,
            timeoutMs: Long,
        ): LSPosedLogcatCommandOutput {
            var process: Process? = null
            val output = StringBuilder()
            return try {
                process = ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .start()

                val readerThread = Thread {
                    runCatching {
                        process.inputStream.bufferedReader().useLines { lines ->
                            lines.forEach { line -> output.appendLine(line) }
                        }
                    }
                }
                readerThread.isDaemon = true
                readerThread.start()

                val completed = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
                if (!completed) {
                    process.destroyForcibly()
                    readerThread.join(200)
                    LSPosedLogcatCommandOutput(
                        output = output.toString().trim(),
                        timedOut = true,
                    )
                } else {
                    readerThread.join(200)
                    LSPosedLogcatCommandOutput(
                        output = output.toString().trim(),
                    )
                }
            } catch (throwable: Throwable) {
                LSPosedLogcatCommandOutput(
                    output = output.toString().trim(),
                    errorMessage = throwable.message ?: throwable.javaClass.simpleName,
                )
            } finally {
                process?.destroy()
            }
        }
    }
}
