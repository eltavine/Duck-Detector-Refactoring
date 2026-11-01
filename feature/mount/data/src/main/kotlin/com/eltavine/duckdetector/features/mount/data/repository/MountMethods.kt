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
import com.eltavine.duckdetector.features.mount.data.native.MountNativeSnapshot
import com.eltavine.duckdetector.features.mount.data.probes.ShellTmpConcealmentProbeResult
import com.eltavine.duckdetector.features.mount.domain.MountAnonymousDeviceState
import com.eltavine.duckdetector.features.mount.domain.MountFinding
import com.eltavine.duckdetector.features.mount.domain.MountFindingGroup
import com.eltavine.duckdetector.features.mount.domain.MountFindingOrigin
import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity
import com.eltavine.duckdetector.features.mount.domain.MountMethodOutcome
import com.eltavine.duckdetector.features.mount.domain.MountMethodResult
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextExposure
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextNamespaceAssessment
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextReport
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextState

internal fun buildMethods(
    snapshot: MountNativeSnapshot,
    preloadResult: EarlyMountPreloadResult,
    shellTmpResult: ShellTmpConcealmentProbeResult,
    zygoteNext: MountZygoteNextReport,
    findings: List<MountFinding>,
): List<MountMethodResult> {
    val pathDanger = if (snapshot.dataAdbDetected) 1 else 0
    val mountsDanger = listOf(snapshot.magiskMountDetected, snapshot.ksuOverlayDetected, snapshot.rootMountArtifactDetected).count { it }
    val mountsWarning = listOf(snapshot.systemRwDetected, snapshot.overlayMountDetected, snapshot.loopDeviceDetected).count { it }
    val infoDanger = findings.count {
        it.origin != MountFindingOrigin.STARTUP_PRELOAD &&
            it.group == MountFindingGroup.CONSISTENCY && it.severity == MountFindingSeverity.DANGER
    }
    val pathObserved = snapshot.findings.any { it.group == "ARTIFACTS" && it.severity == "INFO" }
    val infoObserved = snapshot.findings.any { it.group == "CONSISTENCY" && it.severity == "INFO" } || listOf(
        snapshot.inconsistentMountDetected, snapshot.statxMntIdMismatch, snapshot.bindMountDetected,
        snapshot.mountOptionsAnomaly, snapshot.mountIdLoopholeDetected,
        snapshot.mountPropagationAnomaly, snapshot.namespaceAnomalyDetected,
    ).any { it }
    val fsWarning = listOf(
        snapshot.systemFsTypeAnomaly,
        snapshot.tmpfsSizeAnomaly,
        snapshot.suspiciousTmpfsDetected,
    ).count { it }

    return listOf(
        MountMethodResult(
            label = "Startup preload",
            summary = when {
                !preloadResult.available -> "Unavailable"
                preloadResult.hasDangerSignal -> "${preloadResult.findingCount} hit(s)"
                preloadResult.hasWarningSignal -> "${preloadResult.findingCount} signal(s)"
                preloadResult.findingCount > 0 -> "Observation"
                else -> "Clean"
            },
            outcome = when {
                !preloadResult.available -> MountMethodOutcome.SUPPORT
                preloadResult.hasDangerSignal -> MountMethodOutcome.DANGER
                preloadResult.hasWarningSignal -> MountMethodOutcome.WARNING
                preloadResult.findingCount > 0 -> MountMethodOutcome.SUPPORT
                else -> MountMethodOutcome.CLEAN
            },
            detail = "Transparent NativeActivity launcher runs early namespace and mount checks before MainActivity starts.",
        ),
        buildZygoteNextMethod(zygoteNext),
        MountMethodResult(
            label = "Anonymous device minors",
            summary = snapshot.anonymousDeviceState.summary,
            outcome = if (snapshot.anonymousDeviceState == MountAnonymousDeviceState.NO_GAPS) {
                MountMethodOutcome.CLEAN
            } else {
                MountMethodOutcome.SUPPORT
            },
            detail = snapshot.anonymousDeviceDetail.ifBlank {
                "Anonymous-device observations were not collected by the native layer."
            },
        ),
        MountMethodResult(
            label = "Path probes",
            summary = when {
                pathDanger > 0 -> "$pathDanger hit(s)"
                pathObserved || snapshot.busyboxDetected || snapshot.debugRamdiskDetected || snapshot.hybridMountDetected || snapshot.metaHybridMountDetected -> "Observation"
                snapshot.permissionDenied > 0 -> "Partial"
                snapshot.permissionTotal > 0 -> "Clean"
                else -> "Partial"
            },
            outcome = when {
                pathDanger > 0 -> MountMethodOutcome.DANGER
                pathObserved || snapshot.busyboxDetected || snapshot.debugRamdiskDetected || snapshot.hybridMountDetected || snapshot.metaHybridMountDetected -> MountMethodOutcome.SUPPORT
                snapshot.permissionDenied > 0 -> MountMethodOutcome.SUPPORT
                snapshot.permissionTotal > 0 -> MountMethodOutcome.CLEAN
                else -> MountMethodOutcome.SUPPORT
            },
            detail = "Busybox, /data/adb, debug ramdisk payload markers, and hybrid framework path checks.",
        ),
        MountMethodResult(
            label = "Shell tmp view",
            summary = when {
                !shellTmpResult.available -> "Unavailable"
                shellTmpResult.hasDanger -> "${shellTmpResult.findings.size} hit(s)"
                shellTmpResult.hasWarning -> "${shellTmpResult.findings.size} signal(s)"
                shellTmpResult.findings.isNotEmpty() -> "Observation"
                else -> "Clean"
            },
            outcome = when {
                !shellTmpResult.available -> MountMethodOutcome.SUPPORT
                shellTmpResult.hasDanger -> MountMethodOutcome.DANGER
                shellTmpResult.hasWarning -> MountMethodOutcome.WARNING
                shellTmpResult.findings.isNotEmpty() -> MountMethodOutcome.SUPPORT
                else -> MountMethodOutcome.CLEAN
            },
            detail = "Checks whether /data/local/tmp is selectively hidden or remapped compared with its parent and with /proc/self/mountinfo. ${shellTmpResult.detail}",
        ),
        MountMethodResult(
            label = "/proc/self/mounts",
            summary = when {
                !snapshot.mountsReadable -> "Unavailable"
                mountsDanger > 0 -> "$mountsDanger hit(s)"
                mountsWarning > 0 -> "$mountsWarning review item(s)"
                snapshot.dmVerityBypassDetected || snapshot.findings.any { it.group == "RUNTIME" && it.severity == "INFO" } -> "Source observed"
                else -> "Clean"
            },
            outcome = when {
                !snapshot.mountsReadable -> MountMethodOutcome.SUPPORT
                mountsDanger > 0 -> MountMethodOutcome.DANGER
                mountsWarning > 0 -> MountMethodOutcome.WARNING
                snapshot.dmVerityBypassDetected || snapshot.findings.any { it.group == "RUNTIME" && it.severity == "INFO" } -> MountMethodOutcome.SUPPORT
                else -> MountMethodOutcome.CLEAN
            },
            detail = "Runtime mount table scan for Magisk paths, writable system partitions, overlays, loop devices, and observed source paths.",
        ),
        MountMethodResult(
            label = "/proc/self/maps",
            summary = when {
                !snapshot.mapsReadable -> "Unavailable"
                snapshot.zygiskCacheDetected -> "Zygisk/Riru"
                else -> "Clean"
            },
            outcome = when {
                !snapshot.mapsReadable -> MountMethodOutcome.SUPPORT
                snapshot.zygiskCacheDetected -> MountMethodOutcome.DANGER
                else -> MountMethodOutcome.CLEAN
            },
            detail = "Memory-map scan for Zygisk, Riru, and Magisk-hidden library paths.",
        ),
        MountMethodResult(
            label = "/proc/self/mountinfo",
            summary = when {
                !snapshot.mountInfoReadable -> "Unavailable"
                infoDanger > 0 -> "$infoDanger hit(s)"
                infoObserved -> "Observation"
                else -> "Clean"
            },
            outcome = when {
                !snapshot.mountInfoReadable -> MountMethodOutcome.SUPPORT
                infoDanger > 0 -> MountMethodOutcome.DANGER
                infoObserved -> MountMethodOutcome.SUPPORT
                else -> MountMethodOutcome.CLEAN
            },
            detail = "Mountinfo root-field, propagation, mount-ID, and namespace-consistency checks.",
        ),
        MountMethodResult(
            label = "Filesystem probes",
            summary = when {
                !snapshot.filesystemsReadable && !snapshot.mountsReadable -> "Partial"
                snapshot.systemFsTypeAnomaly -> "Overlayfs system"
                fsWarning > 0 -> "$fsWarning signal(s)"
                snapshot.overlayfsKernelSupport -> "Support present"
                else -> "Clean"
            },
            outcome = when {
                snapshot.systemFsTypeAnomaly -> MountMethodOutcome.WARNING
                fsWarning > 0 -> MountMethodOutcome.WARNING
                snapshot.overlayfsKernelSupport -> MountMethodOutcome.SUPPORT
                !snapshot.filesystemsReadable && !snapshot.mountsReadable -> MountMethodOutcome.SUPPORT
                else -> MountMethodOutcome.CLEAN
            },
            detail = "Overlayfs support, system filesystem type, and suspicious tmpfs sizing checks.",
        ),
        MountMethodResult(
            label = "statx cross-check",
            summary = when {
                !snapshot.statxSupported -> "Unavailable"
                !snapshot.mountInfoReadable -> "Partial"
                snapshot.statxMntIdMismatch || snapshot.statxMountRootAnomaly -> "Observation"
                snapshot.statxMountRootAttribute -> "Mount root"
                else -> "Clean"
            },
            outcome = when {
                !snapshot.statxSupported || !snapshot.mountInfoReadable -> MountMethodOutcome.SUPPORT
                snapshot.statxMntIdMismatch || snapshot.statxMountRootAnomaly -> MountMethodOutcome.SUPPORT
                snapshot.statxMountRootAttribute -> MountMethodOutcome.SUPPORT
                else -> MountMethodOutcome.CLEAN
            },
            detail = "Reports returned statx mount-ID and mount-root fields. Missing fields or syscall errors limit coverage; non-atomic differences do not establish tampering.",
        ),
    )
}

internal fun buildZygoteNextMethod(
    zygoteNext: MountZygoteNextReport,
): MountMethodResult {
    return MountMethodResult(
        label = "Zygote next mount view",
        summary = when (zygoteNext.state) {
            MountZygoteNextState.PENDING -> "Pending"
            MountZygoteNextState.UNSUPPORTED -> "Requires Android 17"
            MountZygoteNextState.UNAVAILABLE -> "Unavailable"
            MountZygoteNextState.READY -> when {
                zygoteNext.exposure == MountZygoteNextExposure.ROOT_MOUNT_EXPOSURE ->
                    "ROOT_MOUNT_EXPOSURE: ${zygoteNext.dangerousMarkers.size} root mount(s)"

                zygoteNext.namespaceAssessment == MountZygoteNextNamespaceAssessment.PRIVATE_ANOMALY ->
                    "Namespace observation"

                zygoteNext.namespaceAssessment == MountZygoteNextNamespaceAssessment.INCONSISTENT ->
                    "Namespace observation"

                !zygoteNext.hasInitNamespaceCoverage -> "Coverage unverified"
                else -> "Clean"
            }
        },
        outcome = when (zygoteNext.state) {
            MountZygoteNextState.PENDING,
            MountZygoteNextState.UNSUPPORTED,
            MountZygoteNextState.UNAVAILABLE -> MountMethodOutcome.SUPPORT

            MountZygoteNextState.READY -> when {
                zygoteNext.leakDetected -> MountMethodOutcome.DANGER
                zygoteNext.namespaceAssessment == MountZygoteNextNamespaceAssessment.PRIVATE_ANOMALY ||
                    zygoteNext.namespaceAssessment == MountZygoteNextNamespaceAssessment.INCONSISTENT -> MountMethodOutcome.SUPPORT

                !zygoteNext.hasInitNamespaceCoverage -> MountMethodOutcome.SUPPORT
                else -> MountMethodOutcome.CLEAN
            }
        },
        detail = buildZygoteNextMethodDetail(zygoteNext),
    )
}

private fun buildZygoteNextMethodDetail(report: MountZygoteNextReport): String {
    return when (report.state) {
        MountZygoteNextState.PENDING -> "Waiting for the Android 17 native isolated service."
        MountZygoteNextState.UNSUPPORTED,
        MountZygoteNextState.UNAVAILABLE -> report.errorDetail

        MountZygoteNextState.READY -> buildString {
            append("Compares the classic app mount view with an Android 17 zygote_next native isolated process. ")
            append(report.namespaceAssessmentDetail)
            append(' ')
            append("main={propagation=")
            append(report.mainPropagation.ifBlank { "unclassified" })
            append(", mounts=${report.mainMountCount}, ids=")
            append(report.mainMinimumMountId)
            append("..")
            append(report.mainMaximumMountId)
            append("}; isolated={propagation=")
            append(report.isolatedPropagation.ifBlank { "unclassified" })
            append(", mounts=${report.isolatedMountCount}, ids=")
            append(report.isolatedMinimumMountId)
            append("..")
            append(report.isolatedMaximumMountId)
            append("}. Shared propagation plus lower root/minimum and anchor mount IDs is the stock route signature; root-managed mount records are the direct exposure signal.")
        }
    }
}
