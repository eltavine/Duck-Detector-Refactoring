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

import android.content.Context
import com.eltavine.duckdetector.capability.earlypreload.data.EarlyMountPreloadResult
import com.eltavine.duckdetector.capability.earlypreload.data.EarlyMountPreloadStore
import com.eltavine.duckdetector.capability.helperprocess.data.HelperProcessProfile
import com.eltavine.duckdetector.capability.helperprocess.data.HelperProcessSnapshot
import com.eltavine.duckdetector.capability.helperprocess.data.IsolatedHelperProbeManager
import com.eltavine.duckdetector.capability.helperprocess.data.ProcMountViewRootToken
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.features.mount.data.native.MountNativeBridge
import com.eltavine.duckdetector.features.mount.data.native.MountNativeSnapshot
import com.eltavine.duckdetector.features.mount.data.probes.ShellTmpConcealmentProbe
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextMountMarker
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextProbeManager
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextProbeResult
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextProbeState
import com.eltavine.duckdetector.features.mount.domain.MountFinding
import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity
import com.eltavine.duckdetector.features.mount.domain.MountImpact
import com.eltavine.duckdetector.features.mount.domain.MountReport
import com.eltavine.duckdetector.features.mount.domain.MountRootToken
import com.eltavine.duckdetector.features.mount.domain.MountStage
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextMarker
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextReport
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class MountRepository(
    context: Context? = null,
    private val nativeBridge: MountNativeBridge = MountNativeBridge(),
    private val preloadResultProvider: () -> EarlyMountPreloadResult = EarlyMountPreloadStore::currentResult,
    private val shellTmpConcealmentProbe: ShellTmpConcealmentProbe = ShellTmpConcealmentProbe(),
    private val isolatedProbeManager: IsolatedHelperProbeManager =
        IsolatedHelperProbeManager(context?.applicationContext),
    private val zygoteNextProbeManager: ZygoteNextProbeManager =
        ZygoteNextProbeManager(context?.applicationContext),
) : DetectorScanner<MountReport> {
    override suspend fun scan(): MountReport = withContext(Dispatchers.IO) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                MountReport.failed(throwable.message ?: "Mount scan failed.")
            }
    }

    private suspend fun scanInternal(): MountReport {
        val snapshotResult = runCatching(nativeBridge::collectSnapshot)
        val procMountView = isolatedProbeManager.collectProcMountView()
        val zygoteNext = zygoteNextProbeManager.collect().toMountReport()
        val snapshot = snapshotResult.getOrElse { throwable ->
            return buildFailedReport(
                message = throwable.message ?: "Native mount snapshot failed.",
                procMountView = procMountView,
                zygoteNext = zygoteNext,
            )
        }
        val preloadResult = preloadResultProvider()
        val shellTmpResult = shellTmpConcealmentProbe.run()
        if (!snapshot.available) {
            return buildFailedReport(
                message = snapshot.collection.explain("Native mount snapshot was unavailable"),
                procMountView = procMountView,
                zygoteNext = zygoteNext,
            )
        }

        val findings = buildFindings(snapshot, preloadResult, shellTmpResult, zygoteNext)
        val impacts = buildImpacts(snapshot, findings)
        val methods = buildMethods(snapshot, preloadResult, shellTmpResult, zygoteNext, findings)

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
            anonymousDeviceState = snapshot.anonymousDeviceState,
            earlyPreloadAvailable = preloadResult.available,
            earlyPreloadDetected = preloadResult.detected,
            earlyPreloadContextValid = preloadResult.isContextValid,
            earlyPreloadFindingCount = preloadResult.findingCount,
            findings = findings,
            impacts = impacts,
            methods = methods,
            zygoteNext = zygoteNext,
        ).withProcMountView(procMountView)
    }

    private fun buildFailedReport(
        message: String,
        procMountView: HelperProcessSnapshot,
        zygoteNext: MountZygoteNextReport,
    ): MountReport {
        return MountReport.failed(message).copy(
            findings = buildZygoteNextFindings(zygoteNext),
            methods = listOf(buildZygoteNextMethod(zygoteNext)),
            zygoteNext = zygoteNext,
        ).withProcMountView(procMountView)
    }

    private fun MountReport.withProcMountView(snapshot: HelperProcessSnapshot): MountReport {
        val available = snapshot.profile == HelperProcessProfile.ISOLATED &&
                snapshot.procMountViewAvailable
        return copy(
            procMountViewProbeAvailable = available,
            procMountViewDistinctCount = snapshot.procMountViewCount,
            procMountViewExpectedCount = snapshot.procMountViewExpected,
            procMountViewPidCount = snapshot.procMountViewPidCount,
            procMountViewDivergent = snapshot.procMountViewDivergent,
            procMountViewTokenHit = snapshot.procMountViewTokenHit,
            procMountViewRootToken = snapshot.procMountViewToken?.toMountRootToken(),
            procMountViewTokenDetail = snapshot.procMountViewTokenDetail,
            procMountViewDetail = snapshot.procMountViewDetail.ifBlank { snapshot.errorDetail },
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
            if (snapshot.systemRwDetected || snapshot.overlayMountDetected || snapshot.loopDeviceDetected) {
                add(
                    MountImpact(
                        text = "Writable, overlaid, or loop-backed system mounts were observed. Development remounts can produce these records; they do not identify a root manager or establish verified-boot state.",
                        severity = MountFindingSeverity.WARNING,
                    ),
                )
            }
            if (snapshot.inconsistentMountDetected || snapshot.statxMntIdMismatch || snapshot.statxMountRootAnomaly) {
                add(
                    MountImpact(
                        text = "Filesystem and statx observations were collected at separate times and may resolve different paths or covering mounts. These observations do not establish mount hiding.",
                        severity = MountFindingSeverity.INFO,
                    ),
                )
            }
            if (findings.any { it.severity == MountFindingSeverity.WARNING } && none { it.severity == MountFindingSeverity.DANGER }) {
                add(
                    MountImpact(
                        text = "Review the listed mount properties in the context of this device and build; a warning alone does not establish root.",
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

    private fun ZygoteNextProbeResult.toMountReport(): MountZygoteNextReport {
        return MountZygoteNextReport(
            state = when (state) {
                ZygoteNextProbeState.UNSUPPORTED -> MountZygoteNextState.UNSUPPORTED
                ZygoteNextProbeState.UNAVAILABLE -> MountZygoteNextState.UNAVAILABLE
                ZygoteNextProbeState.READY -> MountZygoteNextState.READY
            },
            sdkInt = sdkInt,
            mainNamespaceInode = mainProcess.mountNamespaceInode,
            mainUid = mainProcess.uid,
            mainPropagation = mainProcess.rootPropagation,
            mainRootMountId = mainProcess.rootMountId,
            mainMinimumMountId = mainProcess.minimumMountId,
            mainMaximumMountId = mainProcess.maximumMountId,
            mainMountCount = mainProcess.mountCount,
            mainMountIdsByPoint = mainProcess.mountIdsByPoint,
            mainMarkers = mainProcess.markers.map { it.toMountMarker() },
            isolatedNamespaceInode = isolatedProcess.mountNamespaceInode,
            isolatedParentPid = isolatedProcess.parentPid,
            isolatedUid = isolatedProcess.uid,
            isolatedPropagation = isolatedProcess.rootPropagation,
            isolatedRootMountId = isolatedProcess.rootMountId,
            isolatedMinimumMountId = isolatedProcess.minimumMountId,
            isolatedMaximumMountId = isolatedProcess.maximumMountId,
            isolatedMountCount = isolatedProcess.mountCount,
            isolatedMountIdsByPoint = isolatedProcess.mountIdsByPoint,
            isolatedMarkers = isolatedProcess.markers.map { it.toMountMarker() },
            errorDetail = errorDetail,
        )
    }

    private fun ZygoteNextMountMarker.toMountMarker(): MountZygoteNextMarker {
        return MountZygoteNextMarker(
            labels = labels,
            mountPoint = mountPoint,
            mountRoot = mountRoot,
            fileSystemType = fileSystemType,
            source = source,
            rawLine = rawLine,
        )
    }

}

private fun ProcMountViewRootToken.toMountRootToken(): MountRootToken = when (this) {
    ProcMountViewRootToken.MAGISK -> MountRootToken.MAGISK
    ProcMountViewRootToken.KSU -> MountRootToken.KSU
    ProcMountViewRootToken.ADB -> MountRootToken.ADB
}
