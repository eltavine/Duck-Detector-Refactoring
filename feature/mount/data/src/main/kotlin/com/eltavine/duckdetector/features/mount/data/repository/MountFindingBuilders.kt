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
import com.eltavine.duckdetector.features.mount.data.native.MountNativeFinding
import com.eltavine.duckdetector.features.mount.data.native.MountNativeSnapshot
import com.eltavine.duckdetector.features.mount.data.probes.ShellTmpConcealmentProbeResult
import com.eltavine.duckdetector.features.mount.domain.MountFinding
import com.eltavine.duckdetector.features.mount.domain.MountFindingGroup
import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextExposure
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextNamespaceAssessment
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextReport

internal fun MountRepository.buildFindings(
    snapshot: MountNativeSnapshot,
    preloadResult: EarlyMountPreloadResult,
    shellTmpResult: ShellTmpConcealmentProbeResult,
    zygoteNext: MountZygoteNextReport,
): List<MountFinding> {
    val mapped = snapshot.findings.mapIndexed { index, finding ->
        MountFinding(
            id = "native_$index",
            label = finding.label,
            value = finding.value,
            group = finding.group.toGroup(),
            severity = finding.severity.toSeverity(),
            detail = finding.detail.takeIf { it.isNotBlank() },
            detailMonospace = shouldRenderMonospace(finding),
        )
    }

    val informational = buildList {
        add(
            MountFinding(
                id = "anonymous_device_minors",
                label = "Anonymous device minors",
                value = snapshot.anonymousDeviceState.summary,
                group = MountFindingGroup.CONSISTENCY,
                severity = MountFindingSeverity.INFO,
                detail = snapshot.anonymousDeviceDetail.ifBlank {
                    "Anonymous-device diagnostic detail was not collected."
                },
                detailMonospace = true,
            ),
        )
        if (!snapshot.initNamespaceReadable) {
            add(
                MountFinding(
                    id = "init_namespace_scope",
                    label = "Init namespace access",
                    value = "Restricted",
                    group = MountFindingGroup.CONSISTENCY,
                    severity = MountFindingSeverity.INFO,
                    detail = "Reading /proc/1/ns/mnt is normally blocked for unprivileged apps, so namespace comparison coverage is partial.",
                ),
            )
        }
        if (snapshot.permissionTotal > 0 && snapshot.permissionDenied > 0) {
            add(
                MountFinding(
                    id = "permission_coverage",
                    label = "Path coverage",
                    value = "${coveragePercent(snapshot)}%",
                    group = MountFindingGroup.CONSISTENCY,
                    severity = MountFindingSeverity.INFO,
                    detail = "Accessible checks: ${snapshot.permissionAccessible}/${snapshot.permissionTotal}. Permission-denied checks: ${snapshot.permissionDenied}. Restricted visibility is not evidence of root.",
                ),
            )
        }
        if (snapshot.overlayfsKernelSupport && mapped.none { it.label == "Overlayfs kernel support" }) {
            add(
                MountFinding(
                    id = "overlayfs_support",
                    label = "Overlayfs kernel support",
                    value = "Present",
                    group = MountFindingGroup.FILESYSTEM,
                    severity = MountFindingSeverity.INFO,
                    detail = "Kernel overlayfs support exists. This only matters when combined with suspicious mount behavior.",
                ),
            )
        }
    }

    val runtimeAndInformational = mapped + informational + buildZygoteNextFindings(zygoteNext)
    val withShellTmp = runtimeAndInformational + shellTmpResult.findings
    val preloadFindings = buildPreloadFindings(preloadResult)
    val merged = mergePreloadFindings(
        baseFindings = withShellTmp,
        preloadFindings = preloadFindings,
    )

    return merged.sortedWith(
        compareBy<MountFinding> { severityPriority(it.severity) }
            .thenBy { groupPriority(it.group) }
            .thenBy { it.label },
    )
}

internal fun MountRepository.buildZygoteNextFindings(
    zygoteNext: MountZygoteNextReport,
): List<MountFinding> {
    return buildList {
        if (zygoteNext.namespaceAssessment == MountZygoteNextNamespaceAssessment.PRIVATE_ANOMALY ||
            zygoteNext.namespaceAssessment == MountZygoteNextNamespaceAssessment.INCONSISTENT
        ) {
            add(
                MountFinding(
                    id = "zygote_next_namespace_anomaly",
                    label = "Zygote next namespace observation",
                    value = "Coverage unverified",
                    group = MountFindingGroup.CONSISTENCY,
                    severity = MountFindingSeverity.INFO,
                    detail = zygoteNext.namespaceAssessmentDetail,
                ),
            )
        }
        if (zygoteNext.exposure == MountZygoteNextExposure.ROOT_MOUNT_EXPOSURE) {
            add(
                MountFinding(
                    id = "zygote_next_root_mount_exposure",
                    label = "Root mount exposure",
                    value = "ROOT_MOUNT_EXPOSURE",
                    group = MountFindingGroup.RUNTIME,
                    severity = MountFindingSeverity.DANGER,
                    detail = zygoteNext.dangerousMarkers.joinToString("\n") { marker ->
                        "${marker.labels.joinToString("+")}: ${marker.mountPoint} " +
                            "[${marker.fileSystemType}; root=${marker.mountRoot}; source=${marker.source}]"
                    },
                    detailMonospace = true,
                ),
            )
        }
    }
}

internal fun MountRepository.shouldRenderMonospace(finding: MountNativeFinding): Boolean {
    return finding.detail.contains("/proc/") ||
            finding.detail.contains("/system/") ||
            finding.detail.contains("/data/adb") ||
            finding.detail.contains("0x")
}

internal fun String.toGroup(): MountFindingGroup {
    return when (uppercase()) {
        "ARTIFACTS" -> MountFindingGroup.ARTIFACTS
        "RUNTIME" -> MountFindingGroup.RUNTIME
        "FILESYSTEM" -> MountFindingGroup.FILESYSTEM
        "CONSISTENCY" -> MountFindingGroup.CONSISTENCY
        else -> MountFindingGroup.CONSISTENCY
    }
}

internal fun String.toSeverity(): MountFindingSeverity {
    return when (uppercase()) {
        "DANGER" -> MountFindingSeverity.DANGER
        "WARNING" -> MountFindingSeverity.WARNING
        "SAFE" -> MountFindingSeverity.SAFE
        else -> MountFindingSeverity.INFO
    }
}

internal fun MountRepository.severityPriority(severity: MountFindingSeverity): Int {
    return when (severity) {
        MountFindingSeverity.DANGER -> 0
        MountFindingSeverity.WARNING -> 1
        MountFindingSeverity.INFO -> 2
        MountFindingSeverity.SAFE -> 3
    }
}

internal fun MountRepository.groupPriority(group: MountFindingGroup): Int {
    return when (group) {
        MountFindingGroup.ARTIFACTS -> 0
        MountFindingGroup.RUNTIME -> 1
        MountFindingGroup.FILESYSTEM -> 2
        MountFindingGroup.CONSISTENCY -> 3
    }
}

internal fun MountRepository.coveragePercent(snapshot: MountNativeSnapshot): Int {
    return if (snapshot.permissionTotal <= 0) {
        100
    } else {
        ((snapshot.permissionAccessible.toDouble() / snapshot.permissionTotal.toDouble()) * 100.0).toInt()
    }
}
