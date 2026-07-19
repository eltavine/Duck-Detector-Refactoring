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

package com.eltavine.duckdetector.features.dangerousapps.data.probes

import java.util.concurrent.TimeUnit

class SceneDebugfsContextProbe(
    private val transport: Transport = ProcessTransport(),
) {

    fun probe(): SceneDebugfsContextProbeResult {
        val mountPoints = extractDevMountPoints(transport.mountLines())
        val contexts = mountPoints.associateWith(transport::selinuxContext)
        return evaluate(mountPoints, contexts)
    }

    internal fun evaluate(
        mountPoints: List<String>,
        contexts: Map<String, String?>,
    ): SceneDebugfsContextProbeResult {
        val detectedMounts = mountPoints.filter { mountPoint ->
            contexts[mountPoint]?.trim()?.trimEnd('\u0000') == DEBUGFS_CONTEXT
        }
        return SceneDebugfsContextProbeResult(
            detected = detectedMounts.isNotEmpty(),
            detail = detectedMounts
                .takeIf { it.isNotEmpty() }
                ?.joinToString(prefix = "Scene debugfs context: "),
        )
    }

    private fun extractDevMountPoints(lines: List<String>): List<String> {
        return lines.mapNotNull { line ->
            val fields = line.split(' ')
            fields.getOrNull(2)
                ?.takeIf { line.contains("/dev") && fields.getOrNull(1) == "on" }
        }.distinct()
    }

    interface Transport {
        fun mountLines(): List<String>

        fun selinuxContext(path: String): String?
    }

    class ProcessTransport : Transport {
        override fun mountLines(): List<String> = runCommand("mount")

        override fun selinuxContext(path: String): String? {
            return runCommand("stat", "-c", "%C", path).singleOrNull()
        }

        private fun runCommand(vararg command: String): List<String> {
            var process: Process? = null
            return try {
                process = ProcessBuilder(command.toList()).redirectErrorStream(true).start()
                val output = process.inputStream.bufferedReader().use { it.readLines() }
                if (!process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    process.destroyForcibly()
                    emptyList()
                } else if (process.exitValue() == 0) {
                    output
                } else {
                    emptyList()
                }
            } catch (_: Exception) {
                emptyList()
            } finally {
                process?.destroy()
            }
        }
    }

    data class SceneDebugfsContextProbeResult(
        val detected: Boolean,
        val detail: String? = null,
    )

    private companion object {
        private const val COMMAND_TIMEOUT_SECONDS = 2L
        private const val DEBUGFS_CONTEXT = "u:object_r:debugfs:s0"
    }
}
