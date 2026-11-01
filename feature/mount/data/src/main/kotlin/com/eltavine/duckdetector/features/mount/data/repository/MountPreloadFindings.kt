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

package com.eltavine.duckdetector.features.mount.data.repository

import com.eltavine.duckdetector.capability.earlypreload.data.EarlyMountPreloadResult
import com.eltavine.duckdetector.capability.earlypreload.data.EarlyMountPreloadSignal
import com.eltavine.duckdetector.features.mount.domain.MountFinding
import com.eltavine.duckdetector.features.mount.domain.MountFindingGroup
import com.eltavine.duckdetector.features.mount.domain.MountFindingOrigin
import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity

internal fun buildPreloadFindings(result: EarlyMountPreloadResult): List<MountFinding> {
    if (!result.available) {
        return emptyList()
    }

    return buildList {
        if (result.mntStringsDetected) {
            add(
                MountFinding(
                    id = "early_preload_mnt_strings",
                    label = "mntent strings residue",
                    value = result.mntStringsSource.ifBlank {
                        result.mntStringsTarget.ifBlank { "Detected" }
                    },
                    group = MountFindingGroup.ARTIFACTS,
                    severity = MountFindingSeverity.DANGER,
                    detail = preloadSignalDetail(
                        result = result,
                        signal = EarlyMountPreloadSignal.MNT_STRINGS,
                        extras = listOfNotNull(
                            result.mntStringsSource.takeIf { it.isNotBlank() }
                                ?.let { "source=$it" },
                            result.mntStringsTarget.takeIf { it.isNotBlank() }
                                ?.let { "target=$it" },
                            result.mntStringsFs.takeIf { it.isNotBlank() }?.let { "fs=$it" },
                        ),
                    ),
                    detailMonospace = true,
                    origin = MountFindingOrigin.STARTUP_PRELOAD,
                ),
            )
        }
        if (result.futileHideDetected) {
            add(
                MountFinding(
                    id = "early_preload_futile_hide",
                    label = "Proc inode timestamps",
                    value = "ctime drift",
                    group = MountFindingGroup.CONSISTENCY,
                    severity = MountFindingSeverity.INFO,
                    detail = preloadSignalDetail(
                        result = result,
                        signal = EarlyMountPreloadSignal.FUTILE_HIDE,
                        extras = listOf(
                            "ns/mnt ctime delta=${result.nsMntCtimeDeltaNs}ns",
                            "mountinfo ctime delta=${result.mountInfoCtimeDeltaNs}ns",
                        ),
                    ),
                    detailMonospace = true,
                    origin = MountFindingOrigin.STARTUP_PRELOAD,
                ),
            )
        }
        if (result.mountIdGapDetected) {
            add(
                MountFinding(
                    id = "early_preload_mount_id_loophole",
                    label = MOUNT_ID_OBSERVATION_LABEL,
                    value = "Startup preload",
                    group = MountFindingGroup.CONSISTENCY,
                    severity = MountFindingSeverity.INFO,
                    detail = preloadSignalDetail(
                        result = result,
                        signal = EarlyMountPreloadSignal.MOUNT_ID_GAP,
                        extras = listOf(MOUNT_ID_OBSERVATION_EXPLANATION),
                    ),
                    detailMonospace = true,
                    origin = MountFindingOrigin.STARTUP_PRELOAD,
                ),
            )
        }
        if (result.minorDevGapDetected) {
            add(
                MountFinding(
                    id = "early_preload_minor_dev_gap",
                    label = "Minor device observation",
                    value = "Sequence drift",
                    group = MountFindingGroup.CONSISTENCY,
                    severity = MountFindingSeverity.INFO,
                    detail = preloadSignalDetail(
                        result = result,
                        signal = EarlyMountPreloadSignal.MINOR_DEV_GAP,
                    ),
                    detailMonospace = true,
                    origin = MountFindingOrigin.STARTUP_PRELOAD,
                ),
            )
        }
        if (result.peerGroupGapDetected) {
            add(
                MountFinding(
                    id = "early_preload_peer_group_gap",
                    label = "Peer group observation",
                    value = "Startup gap",
                    group = MountFindingGroup.CONSISTENCY,
                    severity = MountFindingSeverity.INFO,
                    detail = preloadSignalDetail(
                        result = result,
                        signal = EarlyMountPreloadSignal.PEER_GROUP_GAP,
                    ),
                    detailMonospace = true,
                    origin = MountFindingOrigin.STARTUP_PRELOAD,
                ),
            )
        }
    }
}

internal fun mergePreloadFindings(
    baseFindings: List<MountFinding>,
    preloadFindings: List<MountFinding>,
): List<MountFinding> {
    if (preloadFindings.isEmpty()) {
        return collapseMountIdFindings(baseFindings.map(::normalizeMountIdObservation))
    }

    val merged = baseFindings.map(::normalizeMountIdObservation).toMutableList()
    val preloadMountId =
        preloadFindings.firstOrNull { it.id == "early_preload_mount_id_loophole" }
            ?.let(::normalizeMountIdObservation)
    val runtimeMountIdFindings = merged.filter { it.isMountIdObservation() }

    if (preloadMountId != null || runtimeMountIdFindings.size > 1) {
        merged.removeAll(runtimeMountIdFindings.toSet())
        mergeMountIdFinding(runtimeMountIdFindings, preloadMountId)?.let(merged::add)
    }

    preloadFindings
        .filterNot { it.id == "early_preload_mount_id_loophole" }
        .forEach(merged::add)

    return merged
}

private fun collapseMountIdFindings(findings: List<MountFinding>): List<MountFinding> {
    val mountIdFindings = findings.filter { it.isMountIdObservation() }
    if (mountIdFindings.size <= 1) {
        return findings
    }

    val merged = findings.toMutableList()
    merged.removeAll(mountIdFindings.toSet())
    mergeMountIdFinding(
        runtimeFindings = mountIdFindings,
        preloadFinding = null
    )?.let(merged::add)
    return merged
}

private fun mergeMountIdFinding(
    runtimeFindings: List<MountFinding>,
    preloadFinding: MountFinding?,
): MountFinding? {
    if (runtimeFindings.isEmpty() && preloadFinding == null) {
        return null
    }

    if (runtimeFindings.size == 1 && preloadFinding == null) {
        return runtimeFindings.first()
    }

    val detailParts = buildList {
        if (preloadFinding != null) {
            add("Startup preload: ${preloadFinding.detail ?: preloadFinding.value}")
        }
        runtimeFindings.forEach { finding ->
            add("Runtime mountinfo: ${finding.detail ?: finding.value}")
        }
    }

    return MountFinding(
        id = if (runtimeFindings.isNotEmpty()) {
            "mount_id_loophole"
        } else {
            "early_preload_mount_id_loophole"
        },
        label = MOUNT_ID_OBSERVATION_LABEL,
        value = when {
            runtimeFindings.isNotEmpty() && preloadFinding != null -> "Startup + runtime"
            runtimeFindings.size > 1 -> "Multiple observations"
            preloadFinding != null -> preloadFinding.value
            else -> runtimeFindings.firstOrNull()?.value ?: "Detected"
        },
        group = MountFindingGroup.CONSISTENCY,
        severity = MountFindingSeverity.INFO,
        detail = detailParts.joinToString(separator = ". ", postfix = "."),
        detailMonospace = runtimeFindings.any { it.detailMonospace } || preloadFinding?.detailMonospace == true,
        origin = when {
            preloadFinding == null -> MountFindingOrigin.RUNTIME
            runtimeFindings.isEmpty() -> MountFindingOrigin.STARTUP_PRELOAD
            else -> MountFindingOrigin.STARTUP_AND_RUNTIME
        },
    )
}

private fun preloadSignalDetail(
    result: EarlyMountPreloadResult,
    signal: EarlyMountPreloadSignal,
    extras: List<String> = emptyList(),
): String {
    val parts = mutableListOf("Source=startup preload")
    if (!result.isContextValid) {
        parts += "context=stale"
    }
    parts += result.messagesFor(signal)
    parts += extras.filter { it.isNotBlank() }
    if (parts.size == 1 && result.details.isNotBlank()) {
        parts += result.details
    }
    return parts.joinToString(separator = " | ")
}

internal const val MOUNT_ID_OBSERVATION_LABEL = "Mount ID discontinuity"
private const val MOUNT_ID_OBSERVATION_EXPLANATION =
    "Mount IDs need not be consecutive. Repeated startup/runtime observations do not establish hidden mounts."

private fun MountFinding.isMountIdObservation(): Boolean =
    label == MOUNT_ID_OBSERVATION_LABEL || label == "Mount ID loophole"

// Stored/legacy payloads may still carry the former label and DANGER severity.
private fun normalizeMountIdObservation(finding: MountFinding): MountFinding =
    if (finding.isMountIdObservation()) {
        finding.copy(
            label = MOUNT_ID_OBSERVATION_LABEL,
            severity = MountFindingSeverity.INFO,
            detail = if (finding.label == "Mount ID loophole") {
                listOfNotNull(finding.detail, MOUNT_ID_OBSERVATION_EXPLANATION).joinToString(" | ")
            } else {
                finding.detail
            },
        )
    } else {
        finding
    }
