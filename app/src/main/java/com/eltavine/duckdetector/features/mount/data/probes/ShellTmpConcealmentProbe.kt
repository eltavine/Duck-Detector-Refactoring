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

package com.eltavine.duckdetector.features.mount.data.probes

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import com.eltavine.duckdetector.features.mount.domain.MountFinding
import com.eltavine.duckdetector.features.mount.domain.MountFindingGroup
import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity
import java.io.File

data class ShellTmpConcealmentProbeResult(
    val available: Boolean,
    val findings: List<MountFinding>,
    val dedicatedMountCount: Int,
    val detail: String,
) {
    val hasDanger: Boolean
        get() = findings.any { it.severity == MountFindingSeverity.DANGER }

    val hasWarning: Boolean
        get() = findings.any { it.severity == MountFindingSeverity.WARNING }
}

internal enum class ShellTmpAccessState {
    ACCESSIBLE,
    MISSING,
    DENIED,
    ERROR,
}

internal data class ShellTmpMountEntry(
    val target: String,
    val fsType: String,
    val source: String,
)

internal data class ShellTmpObservation(
    val parentAccessible: Boolean,
    val accessState: ShellTmpAccessState,
    val javaExists: Boolean,
    val javaDirectory: Boolean,
    val javaCanRead: Boolean,
    val javaListable: Boolean,
    val dedicatedMounts: List<ShellTmpMountEntry>,
)

class ShellTmpConcealmentProbe {

    fun run(): ShellTmpConcealmentProbeResult {
        val parentAccessible = canStat(PARENT_PATH)
        val accessState = resolveAccessState(SHELL_TMP_PATH)
        val path = File(SHELL_TMP_PATH)
        val dedicatedMounts = parseDedicatedMounts(readMountInfo())

        return evaluate(
            ShellTmpObservation(
                parentAccessible = parentAccessible,
                accessState = accessState,
                javaExists = path.exists(),
                javaDirectory = path.isDirectory,
                javaCanRead = path.canRead(),
                javaListable = path.list() != null,
                dedicatedMounts = dedicatedMounts,
            ),
        )
    }

    internal fun evaluate(
        observation: ShellTmpObservation,
    ): ShellTmpConcealmentProbeResult {
        val findings = buildList {
            if (observation.dedicatedMounts.isNotEmpty()) {
                add(
                    MountFinding(
                        id = "shell_tmp_dedicated_mount",
                        label = "Shell tmp dedicated mount",
                        value = observation.dedicatedMounts.first().fsType.ifBlank { "Detected" },
                        group = MountFindingGroup.CONSISTENCY,
                        severity = MountFindingSeverity.DANGER,
                        detail = observation.dedicatedMounts.joinToString(separator = "\n") { entry ->
                            "target=${entry.target} fs=${entry.fsType} source=${entry.source}"
                        },
                        detailMonospace = true,
                    ),
                )
            }

            if (observation.parentAccessible && observation.accessState != ShellTmpAccessState.ACCESSIBLE) {
                add(
                    MountFinding(
                        id = "shell_tmp_view",
                        label = "Shell tmp view",
                        value = when (observation.accessState) {
                            ShellTmpAccessState.MISSING -> "Missing"
                            ShellTmpAccessState.DENIED -> "Denied"
                            ShellTmpAccessState.ERROR -> "Unavailable"
                            ShellTmpAccessState.ACCESSIBLE -> "Accessible"
                        },
                        group = MountFindingGroup.CONSISTENCY,
                        severity = if (observation.dedicatedMounts.isNotEmpty()) {
                            MountFindingSeverity.DANGER
                        } else {
                            MountFindingSeverity.WARNING
                        },
                        detail = "Parent $PARENT_PATH is visible, but $SHELL_TMP_PATH resolved as ${observation.accessState.name.lowercase()}.",
                    ),
                )
            }

            if (observation.accessState == ShellTmpAccessState.ACCESSIBLE &&
                (!observation.javaExists || !observation.javaDirectory)
            ) {
                add(
                    MountFinding(
                        id = "shell_tmp_api_mismatch",
                        label = "Shell tmp API mismatch",
                        value = "Java hidden",
                        group = MountFindingGroup.CONSISTENCY,
                        severity = MountFindingSeverity.DANGER,
                        detail = "Low-level stat reported $SHELL_TMP_PATH as accessible, but Java File reported exists=${observation.javaExists}, dir=${observation.javaDirectory}.",
                    ),
                )
            } else if (observation.accessState != ShellTmpAccessState.ACCESSIBLE &&
                (observation.javaExists || observation.javaDirectory)
            ) {
                add(
                    MountFinding(
                        id = "shell_tmp_api_mismatch",
                        label = "Shell tmp API mismatch",
                        value = "Stat hidden",
                        group = MountFindingGroup.CONSISTENCY,
                        severity = MountFindingSeverity.DANGER,
                        detail = "Low-level stat reported ${observation.accessState.name.lowercase()} for $SHELL_TMP_PATH, but Java File still reported exists=${observation.javaExists}, dir=${observation.javaDirectory}.",
                    ),
                )
            }
        }

        return ShellTmpConcealmentProbeResult(
            available = true,
            findings = findings,
            dedicatedMountCount = observation.dedicatedMounts.size,
            detail = buildString {
                append("parentAccessible=")
                append(observation.parentAccessible)
                append(", accessState=")
                append(observation.accessState)
                append(", dedicatedMounts=")
                append(observation.dedicatedMounts.size)
            },
        )
    }

    private fun canStat(path: String): Boolean {
        return try {
            Os.lstat(path)
            true
        } catch (_: ErrnoException) {
            false
        } catch (_: Throwable) {
            false
        }
    }

    private fun resolveAccessState(path: String): ShellTmpAccessState {
        return try {
            Os.lstat(path)
            ShellTmpAccessState.ACCESSIBLE
        } catch (error: ErrnoException) {
            when (error.errno) {
                OsConstants.ENOENT -> ShellTmpAccessState.MISSING
                OsConstants.EACCES, OsConstants.EPERM -> ShellTmpAccessState.DENIED
                else -> ShellTmpAccessState.ERROR
            }
        } catch (_: Throwable) {
            ShellTmpAccessState.ERROR
        }
    }

    private fun readMountInfo(): String {
        return runCatching {
            File(MOUNTINFO_PATH).takeIf { it.exists() && it.canRead() }?.readText().orEmpty()
        }.getOrDefault("")
    }

    internal fun parseDedicatedMounts(
        raw: String,
    ): List<ShellTmpMountEntry> {
        if (raw.isBlank()) {
            return emptyList()
        }

        return raw.lineSequence().mapNotNull { line ->
            val separator = line.indexOf(" - ")
            if (separator <= 0) {
                return@mapNotNull null
            }
            val leftParts = line.substring(0, separator).trim().split(Regex("\\s+"))
            if (leftParts.size < 5) {
                return@mapNotNull null
            }
            val target = leftParts[4]
            if (target != SHELL_TMP_PATH && !target.startsWith("$SHELL_TMP_PATH/")) {
                return@mapNotNull null
            }
            val rightParts = line.substring(separator + 3).trim().split(Regex("\\s+"))
            if (rightParts.size < 2) {
                return@mapNotNull null
            }
            ShellTmpMountEntry(
                target = target,
                fsType = rightParts[0],
                source = rightParts[1],
            )
        }.toList()
    }

    private companion object {
        private const val PARENT_PATH = "/data/local"
        private const val SHELL_TMP_PATH = "/data/local/tmp"
        private const val MOUNTINFO_PATH = "/proc/self/mountinfo"
    }
}
