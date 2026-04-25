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
import java.io.File

data class LSPosedRuntimeArtifactProbeResult(
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

class LSPosedRuntimeArtifactProbe(
    private val procUnixPath: String = PROC_UNIX_PATH,
    private val procFdPath: String = PROC_FD_PATH,
) {

    fun run(
        appPackageName: String,
    ): LSPosedRuntimeArtifactProbeResult {
        val unixContent = readTextFile(procUnixPath)
        val fdTargets = readFdTargets(procFdPath)
        val environment = runCatching { System.getenv().toMap() }.getOrNull()
        return evaluate(
            unixContent = unixContent,
            fdTargets = fdTargets,
            environment = environment,
            appPackageName = appPackageName,
        )
    }

    internal fun evaluate(
        unixContent: String?,
        fdTargets: List<String>?,
        environment: Map<String, String>?,
        appPackageName: String,
    ): LSPosedRuntimeArtifactProbeResult {
        val excludePatterns = buildExcludePatterns(appPackageName)
        val signals = mutableListOf<LSPosedSignal>()

        unixContent
            ?.lineSequence()
            ?.map { it.trim() }
            ?.filter { it.isNotBlank() }
            ?.filterNot { line -> shouldExclude(line, excludePatterns) }
            ?.filter(::containsFrameworkToken)
            ?.distinct()
            ?.toList()
            ?.takeIf { it.isNotEmpty() }
            ?.let { hits ->
                signals += LSPosedSignal(
                    id = "runtime_unix_sockets",
                    label = "Unix sockets",
                    value = "${hits.size} hit(s)",
                    group = LSPosedSignalGroup.RUNTIME,
                    severity = LSPosedSignalSeverity.DANGER,
                    detail = hits.joinToString(separator = "\n"),
                    detailMonospace = true,
                )
            }

        fdTargets
            ?.map { it.trim() }
            ?.filter { it.isNotBlank() }
            ?.filterNot { target -> shouldExclude(target, excludePatterns) }
            ?.filter(::containsFrameworkToken)
            ?.distinct()
            ?.takeIf { it.isNotEmpty() }
            ?.let { hits ->
                signals += LSPosedSignal(
                    id = "runtime_file_descriptors",
                    label = "File descriptors",
                    value = "${hits.size} hit(s)",
                    group = LSPosedSignalGroup.RUNTIME,
                    severity = LSPosedSignalSeverity.DANGER,
                    detail = hits.joinToString(separator = "\n"),
                    detailMonospace = true,
                )
            }

        environment
            ?.entries
            ?.mapNotNull { (key, value) ->
                buildEnvHit(key, value, excludePatterns)
            }
            ?.distinct()
            ?.takeIf { it.isNotEmpty() }
            ?.let { hits ->
                signals += LSPosedSignal(
                    id = "runtime_environment",
                    label = "Environment variables",
                    value = "${hits.size} hit(s)",
                    group = LSPosedSignalGroup.RUNTIME,
                    severity = LSPosedSignalSeverity.WARNING,
                    detail = hits.joinToString(separator = "\n"),
                    detailMonospace = true,
                )
            }

        val available = unixContent != null || fdTargets != null || environment != null
        return LSPosedRuntimeArtifactProbeResult(
            signals = signals,
            available = available,
            failureReason = if (available) null else "Runtime artifact inputs were not readable from the current app context."
        )
    }

    private fun buildEnvHit(
        key: String,
        value: String,
        excludePatterns: List<String>,
    ): String? {
        val rendered = "$key=$value"
        if (shouldExclude(rendered, excludePatterns)) {
            return null
        }

        val lowerKey = key.lowercase()
        val lowerValue = value.lowercase()
        return when {
            containsFrameworkToken(lowerKey) -> "Name: $rendered".trimToPreview()
            containsFrameworkToken(lowerValue) -> "Value: $rendered".trimToPreview()
            else -> null
        }
    }

    private fun buildExcludePatterns(
        appPackageName: String,
    ): List<String> {
        return buildList {
            addAll(LSPosedProbeSupport.runtimeExcludePatterns)
            add(appPackageName.lowercase())
        }
    }

    private fun shouldExclude(
        text: String,
        excludePatterns: List<String>,
    ): Boolean {
        val lower = text.lowercase()
        return excludePatterns.any { token -> lower.contains(token) }
    }

    private fun readTextFile(
        path: String,
    ): String? {
        val file = File(path)
        if (!file.exists() || !file.canRead()) {
            return null
        }
        return runCatching { file.readText() }.getOrNull()
    }

    private fun readFdTargets(
        directoryPath: String,
    ): List<String>? {
        val directory = File(directoryPath)
        if (!directory.exists() || !directory.isDirectory) {
            return null
        }

        return runCatching {
            directory.listFiles()
                ?.mapNotNull { file ->
                    runCatching { file.canonicalPath }.getOrNull()
                }
                .orEmpty()
        }.getOrNull()
    }

    private companion object {
        private const val PROC_UNIX_PATH = "/proc/self/net/unix"
        private const val PROC_FD_PATH = "/proc/self/fd"
    }
}
