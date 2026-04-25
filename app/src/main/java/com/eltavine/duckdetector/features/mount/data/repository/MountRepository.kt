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

package com.eltavine.duckdetector.features.mount.data.repository

import com.eltavine.duckdetector.core.startup.preload.EarlyMountPreloadResult
import com.eltavine.duckdetector.core.startup.preload.EarlyMountPreloadSignal
import com.eltavine.duckdetector.core.startup.preload.EarlyMountPreloadStore
import com.eltavine.duckdetector.features.mount.data.native.MountNativeBridge
import com.eltavine.duckdetector.features.mount.data.native.MountNativeFinding
import com.eltavine.duckdetector.features.mount.data.native.MountNativeSnapshot
import com.eltavine.duckdetector.features.mount.data.probes.ShellTmpConcealmentProbe
import com.eltavine.duckdetector.features.mount.data.probes.ShellTmpConcealmentProbeResult
import com.eltavine.duckdetector.features.mount.domain.MountFinding
import com.eltavine.duckdetector.features.mount.domain.MountFindingGroup
import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity
import com.eltavine.duckdetector.features.mount.domain.MountImpact
import com.eltavine.duckdetector.features.mount.domain.MountMethodOutcome
import com.eltavine.duckdetector.features.mount.domain.MountMethodResult
import com.eltavine.duckdetector.features.mount.domain.MountReport
import com.eltavine.duckdetector.features.mount.domain.MountStage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class MountRepository(
    private val nativeBridge: MountNativeBridge = MountNativeBridge(),
    private val preloadResultProvider: () -> EarlyMountPreloadResult = EarlyMountPreloadStore::currentResult,
    private val shellTmpConcealmentProbe: ShellTmpConcealmentProbe = ShellTmpConcealmentProbe(),
) {

    suspend fun scan(): MountReport = withContext(Dispatchers.Default) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                MountReport.failed(throwable.message ?: "Mount scan failed.")
            }
    }

    private fun scanInternal(): MountReport {
        val snapshot = nativeBridge.collectSnapshot()
        val preloadResult = sanitizePreloadResult(
            result = preloadResultProvider(),
            snapshot = snapshot,
        )
        val shellTmpResult = shellTmpConcealmentProbe.run()
        if (!snapshot.available) {
            return MountReport.failed("Native mount snapshot was unavailable.")
        }

        val findings = buildFindings(snapshot, preloadResult, shellTmpResult)
        val impacts = buildImpacts(snapshot, findings)
        val methods = buildMethods(snapshot, preloadResult, shellTmpResult)

        return MountReport(
            stage = MountStage.READY,
            nativeAvailable = snapshot.available,
            mountsReadable = snapshot.mountsReadable,
            mountInfoReadable = snapshot.mountInfoReadable,
            mapsReadable = snapshot.mapsReadable,
            filesystemsReadable = snapshot.filesystemsReadable,
            initNamespaceReadable = snapshot.initNamespaceReadable,
            statxSupported = snapshot.statxSupported,
            permissionTotal = snapshot.permissionTotal,
            permissionDenied = snapshot.permissionDenied,
            permissionAccessible = snapshot.permissionAccessible,
            mountEntryCount = snapshot.mountEntryCount,
            mountInfoEntryCount = snapshot.mountInfoEntryCount,
            mapLineCount = snapshot.mapLineCount,
            earlyPreloadAvailable = preloadResult.available,
            earlyPreloadDetected = preloadResult.detected,
            earlyPreloadContextValid = preloadResult.isContextValid,
            earlyPreloadFindingCount = preloadResult.findingCount,
            findings = findings,
            impacts = impacts,
            methods = methods,
        )
    }

    private fun sanitizePreloadResult(
        result: EarlyMountPreloadResult,
        snapshot: MountNativeSnapshot,
    ): EarlyMountPreloadResult {
        if (!result.mountIdGapDetected || snapshot.mountIdLoopholeDetected) {
            return result
        }

        val mountIdMessages = result.messagesFor(EarlyMountPreloadSignal.MOUNT_ID_GAP)
        if (mountIdMessages.isEmpty() || !mountIdMessages.all(::isWeakDataMirrorMountIdGap)) {
            return result
        }

        val filteredFindings = result.findings.filterNot { finding ->
            val type = finding.substringBefore('|')
            val message = finding.split('|').getOrNull(1).orEmpty()
            type == EarlyMountPreloadSignal.MOUNT_ID_GAP.key && isWeakDataMirrorMountIdGap(message)
        }

        return result.copy(
            detected = false,
            detectionMethod = "",
            details = "",
            mountIdGapDetected = false,
            findings = filteredFindings,
        ).normalize()
    }

    private fun isWeakDataMirrorMountIdGap(
        message: String,
    ): Boolean {
        val normalized = message.trim()
        if (SMALL_DATA_MIRROR_SINGLE_MOUNT_ID_REGEX.matches(normalized)) {
            return true
        }

        val match = SMALL_DATA_MIRROR_MULTI_MOUNT_ID_REGEX.matchEntire(normalized) ?: return false
        val missingCount = match.groupValues.getOrNull(1)?.toIntOrNull() ?: return false
        return missingCount <= SMALL_DATA_MIRROR_GAP_THRESHOLD
    }

    private fun buildFindings(
        snapshot: MountNativeSnapshot,
        preloadResult: EarlyMountPreloadResult,
        shellTmpResult: ShellTmpConcealmentProbeResult,
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
                        severity = if (snapshot.permissionDenied * 2 >= snapshot.permissionTotal) {
                            MountFindingSeverity.WARNING
                        } else {
                            MountFindingSeverity.INFO
                        },
                        detail = "Accessible checks: ${snapshot.permissionAccessible}/${snapshot.permissionTotal}. Permission-denied checks: ${snapshot.permissionDenied}.",
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

        val runtimeAndInformational = mapped + informational
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

    private fun buildImpacts(
        snapshot: MountNativeSnapshot,
        findings: List<MountFinding>,
    ): List<MountImpact> {
        return buildList {
            if (findings.any { it.severity == MountFindingSeverity.DANGER }) {
                add(
                    MountImpact(
                        text = "Mount-layer anomalies are strong signals because they describe how the current process actually sees filesystems, overlays, and root-managed bind mounts at runtime.",
                        severity = MountFindingSeverity.DANGER,
                    ),
                )
            }
            if (snapshot.zygiskCacheDetected || snapshot.magiskMountDetected || snapshot.dataAdbDetected) {
                add(
                    MountImpact(
                        text = "Magisk, Zygisk, KernelSU, or APatch-style mount artifacts can be used to present a cleaner filesystem view to selected apps while keeping root tooling active elsewhere.",
                        severity = MountFindingSeverity.DANGER,
                    ),
                )
            }
            if (snapshot.systemRwDetected || snapshot.overlayMountDetected || snapshot.bindMountDetected || snapshot.dmVerityBypassDetected) {
                add(
                    MountImpact(
                        text = "Writable or overlaid system partitions weaken stock verified-boot expectations and often indicate systemless or direct partition modification.",
                        severity = MountFindingSeverity.DANGER,
                    ),
                )
            }
            if (snapshot.mountIdLoopholeDetected || snapshot.inconsistentMountDetected || snapshot.statxMntIdMismatch || snapshot.statxMountRootAnomaly) {
                add(
                    MountImpact(
                        text = "Mount-info and statx contradictions are harder to explain away than a single suspicious path because different kernel-visible mount views disagree.",
                        severity = MountFindingSeverity.DANGER,
                    ),
                )
            }
            if (findings.any { it.severity == MountFindingSeverity.WARNING } && none { it.severity == MountFindingSeverity.DANGER }) {
                add(
                    MountImpact(
                        text = "The mount layer is not clean enough to ignore, but the current evidence is weaker than a direct root-managed overlay or writable-system hit.",
                        severity = MountFindingSeverity.WARNING,
                    ),
                )
            }
            if (isEmpty()) {
                add(
                    MountImpact(
                        text = "No suspicious mount, overlay, namespace, or root-managed filesystem artifact was visible from the current app context.",
                        severity = MountFindingSeverity.SAFE,
                    ),
                )
            }
            add(
                MountImpact(
                    text = "Permission-restricted paths and namespace boundaries can hide part of the mount picture, so combine this card with SU, TEE, kernel, and package detectors.",
                    severity = if (snapshot.permissionDenied > 0) MountFindingSeverity.INFO else MountFindingSeverity.INFO,
                ),
            )
        }
    }

    private fun buildMethods(
        snapshot: MountNativeSnapshot,
        preloadResult: EarlyMountPreloadResult,
        shellTmpResult: ShellTmpConcealmentProbeResult,
    ): List<MountMethodResult> {
        val pathDanger = listOf(
            snapshot.busyboxDetected,
            snapshot.dataAdbDetected,
            snapshot.debugRamdiskDetected,
            snapshot.hybridMountDetected,
            snapshot.metaHybridMountDetected,
        ).count { it }
        val mountsDanger = listOf(
            snapshot.magiskMountDetected,
            snapshot.systemRwDetected,
            snapshot.overlayMountDetected,
            snapshot.ksuOverlayDetected,
            snapshot.loopDeviceDetected,
            snapshot.dmVerityBypassDetected,
        ).count { it }
        val infoDanger = listOf(
            snapshot.inconsistentMountDetected,
            snapshot.mountIdLoopholeDetected,
            snapshot.statxMntIdMismatch,
            snapshot.bindMountDetected,
            snapshot.mountOptionsAnomaly,
        ).count { it }
        val fsWarning = listOf(
            snapshot.overlayfsKernelSupport,
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
                    else -> "Clean"
                },
                outcome = when {
                    !preloadResult.available -> MountMethodOutcome.SUPPORT
                    preloadResult.hasDangerSignal -> MountMethodOutcome.DANGER
                    preloadResult.hasWarningSignal -> MountMethodOutcome.WARNING
                    else -> MountMethodOutcome.CLEAN
                },
                detail = "Transparent NativeActivity launcher runs early namespace and mount checks before MainActivity starts.",
            ),
            MountMethodResult(
                label = "Path probes",
                summary = when {
                    pathDanger > 0 -> "$pathDanger hit(s)"
                    snapshot.permissionTotal > 0 -> "Clean"
                    else -> "Partial"
                },
                outcome = when {
                    pathDanger > 0 -> MountMethodOutcome.DANGER
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
                    else -> "Clean"
                },
                outcome = when {
                    !shellTmpResult.available -> MountMethodOutcome.SUPPORT
                    shellTmpResult.hasDanger -> MountMethodOutcome.DANGER
                    shellTmpResult.hasWarning -> MountMethodOutcome.WARNING
                    else -> MountMethodOutcome.CLEAN
                },
                detail = "Checks whether /data/local/tmp is selectively hidden or remapped compared with its parent and with /proc/self/mountinfo. ${shellTmpResult.detail}",
            ),
            MountMethodResult(
                label = "/proc/self/mounts",
                summary = when {
                    !snapshot.mountsReadable -> "Unavailable"
                    mountsDanger > 0 -> "$mountsDanger hit(s)"
                    else -> "Clean"
                },
                outcome = when {
                    !snapshot.mountsReadable -> MountMethodOutcome.SUPPORT
                    mountsDanger > 0 -> MountMethodOutcome.DANGER
                    else -> MountMethodOutcome.CLEAN
                },
                detail = "Runtime mount table scan for Magisk paths, writable system partitions, overlays, loop devices, and dm-verity bypass patterns.",
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
                    snapshot.mountPropagationAnomaly || snapshot.namespaceAnomalyDetected -> "Review"
                    else -> "Clean"
                },
                outcome = when {
                    !snapshot.mountInfoReadable -> MountMethodOutcome.SUPPORT
                    infoDanger > 0 -> MountMethodOutcome.DANGER
                    snapshot.mountPropagationAnomaly || snapshot.namespaceAnomalyDetected -> MountMethodOutcome.WARNING
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
                    else -> "Clean"
                },
                outcome = when {
                    snapshot.systemFsTypeAnomaly -> MountMethodOutcome.DANGER
                    fsWarning > 0 -> MountMethodOutcome.WARNING
                    !snapshot.filesystemsReadable && !snapshot.mountsReadable -> MountMethodOutcome.SUPPORT
                    else -> MountMethodOutcome.CLEAN
                },
                detail = "Overlayfs support, system filesystem type, and suspicious tmpfs sizing checks.",
            ),
            MountMethodResult(
                label = "statx cross-check",
                summary = when {
                    !snapshot.statxSupported -> "Unsupported"
                    snapshot.statxMntIdMismatch || snapshot.statxMountRootAnomaly -> "Anomaly"
                    else -> "Clean"
                },
                outcome = when {
                    !snapshot.statxSupported -> MountMethodOutcome.SUPPORT
                    snapshot.statxMntIdMismatch || snapshot.statxMountRootAnomaly -> MountMethodOutcome.DANGER
                    else -> MountMethodOutcome.CLEAN
                },
                detail = "Mount-ID and mount-root cross-checks using statx where the kernel exposes those fields.",
            ),
        )
    }

    private fun shouldRenderMonospace(finding: MountNativeFinding): Boolean {
        return finding.detail.contains("/proc/") ||
                finding.detail.contains("/system/") ||
                finding.detail.contains("/data/adb") ||
                finding.detail.contains("0x")
    }

    private fun buildPreloadFindings(result: EarlyMountPreloadResult): List<MountFinding> {
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
                    ),
                )
            }
            if (result.futileHideDetected) {
                add(
                    MountFinding(
                        id = "early_preload_futile_hide",
                        label = "Futile hide",
                        value = "ctime drift",
                        group = MountFindingGroup.CONSISTENCY,
                        severity = MountFindingSeverity.DANGER,
                        detail = preloadSignalDetail(
                            result = result,
                            signal = EarlyMountPreloadSignal.FUTILE_HIDE,
                            extras = listOf(
                                "ns/mnt ctime delta=${result.nsMntCtimeDeltaNs}ns",
                                "mountinfo ctime delta=${result.mountInfoCtimeDeltaNs}ns",
                            ),
                        ),
                        detailMonospace = true,
                    ),
                )
            }
            if (result.mountIdGapDetected) {
                add(
                    MountFinding(
                        id = "early_preload_mount_id_loophole",
                        label = "Mount ID loophole",
                        value = "Startup preload",
                        group = MountFindingGroup.CONSISTENCY,
                        severity = MountFindingSeverity.DANGER,
                        detail = preloadSignalDetail(
                            result = result,
                            signal = EarlyMountPreloadSignal.MOUNT_ID_GAP,
                        ),
                        detailMonospace = true,
                    ),
                )
            }
            if (result.minorDevGapDetected) {
                add(
                    MountFinding(
                        id = "early_preload_minor_dev_gap",
                        label = "Minor device gap",
                        value = "Sequence drift",
                        group = MountFindingGroup.CONSISTENCY,
                        severity = MountFindingSeverity.WARNING,
                        detail = preloadSignalDetail(
                            result = result,
                            signal = EarlyMountPreloadSignal.MINOR_DEV_GAP,
                        ),
                        detailMonospace = true,
                    ),
                )
            }
            if (result.peerGroupGapDetected) {
                add(
                    MountFinding(
                        id = "early_preload_peer_group_gap",
                        label = "Peer group gap",
                        value = "Startup gap",
                        group = MountFindingGroup.CONSISTENCY,
                        severity = MountFindingSeverity.WARNING,
                        detail = preloadSignalDetail(
                            result = result,
                            signal = EarlyMountPreloadSignal.PEER_GROUP_GAP,
                        ),
                        detailMonospace = true,
                    ),
                )
            }
        }
    }

    private fun mergePreloadFindings(
        baseFindings: List<MountFinding>,
        preloadFindings: List<MountFinding>,
    ): List<MountFinding> {
        if (preloadFindings.isEmpty()) {
            return collapseMountIdFindings(baseFindings)
        }

        val merged = baseFindings.toMutableList()
        val preloadMountId =
            preloadFindings.firstOrNull { it.id == "early_preload_mount_id_loophole" }
        val runtimeMountIdFindings = merged.filter { it.label == "Mount ID loophole" }

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
        val mountIdFindings = findings.filter { it.label == "Mount ID loophole" }
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
            label = "Mount ID loophole",
            value = when {
                runtimeFindings.isNotEmpty() && preloadFinding != null -> "Startup + runtime"
                runtimeFindings.size > 1 -> "Multiple gaps"
                preloadFinding != null -> preloadFinding.value
                else -> runtimeFindings.firstOrNull()?.value ?: "Detected"
            },
            group = MountFindingGroup.CONSISTENCY,
            severity = MountFindingSeverity.DANGER,
            detail = detailParts.joinToString(separator = ". ", postfix = "."),
            detailMonospace = runtimeFindings.any { it.detailMonospace } || preloadFinding?.detailMonospace == true,
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

    private fun String.toGroup(): MountFindingGroup {
        return when (uppercase()) {
            "ARTIFACTS" -> MountFindingGroup.ARTIFACTS
            "RUNTIME" -> MountFindingGroup.RUNTIME
            "FILESYSTEM" -> MountFindingGroup.FILESYSTEM
            "CONSISTENCY" -> MountFindingGroup.CONSISTENCY
            else -> MountFindingGroup.CONSISTENCY
        }
    }

    private fun String.toSeverity(): MountFindingSeverity {
        return when (uppercase()) {
            "DANGER" -> MountFindingSeverity.DANGER
            "WARNING" -> MountFindingSeverity.WARNING
            "SAFE" -> MountFindingSeverity.SAFE
            else -> MountFindingSeverity.INFO
        }
    }

    private fun severityPriority(severity: MountFindingSeverity): Int {
        return when (severity) {
            MountFindingSeverity.DANGER -> 0
            MountFindingSeverity.WARNING -> 1
            MountFindingSeverity.INFO -> 2
            MountFindingSeverity.SAFE -> 3
        }
    }

    private fun groupPriority(group: MountFindingGroup): Int {
        return when (group) {
            MountFindingGroup.ARTIFACTS -> 0
            MountFindingGroup.RUNTIME -> 1
            MountFindingGroup.FILESYSTEM -> 2
            MountFindingGroup.CONSISTENCY -> 3
        }
    }

    private fun coveragePercent(snapshot: MountNativeSnapshot): Int {
        return if (snapshot.permissionTotal <= 0) {
            100
        } else {
            ((snapshot.permissionAccessible.toDouble() / snapshot.permissionTotal.toDouble()) * 100.0).toInt()
        }
    }

    private companion object {
        private const val SMALL_DATA_MIRROR_GAP_THRESHOLD = 2
        private val SMALL_DATA_MIRROR_SINGLE_MOUNT_ID_REGEX =
            Regex("""Missing mount ID \d+ before /data_mirror(?:\b.*)?""")
        private val SMALL_DATA_MIRROR_MULTI_MOUNT_ID_REGEX =
            Regex("""Missing (\d+) mount IDs before /data_mirror(?:\b.*)?""")
    }
}
