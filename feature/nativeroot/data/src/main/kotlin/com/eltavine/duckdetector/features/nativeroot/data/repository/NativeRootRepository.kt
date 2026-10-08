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

package com.eltavine.duckdetector.features.nativeroot.data.repository

import android.content.Context
import android.os.SystemClock
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.features.nativeroot.data.native.NativeRootNativeBridge
import com.eltavine.duckdetector.features.nativeroot.data.native.NativeRootNativeFinding
import com.eltavine.duckdetector.features.nativeroot.data.probes.CgroupProcessLeakProbe
import com.eltavine.duckdetector.features.nativeroot.data.probes.KernelSuManagerFingerprintProbe
import com.eltavine.duckdetector.features.nativeroot.data.probes.KernelSuThroneHuntProbe
import com.eltavine.duckdetector.features.nativeroot.data.probes.KernelSuThroneHuntRound
import com.eltavine.duckdetector.features.nativeroot.data.probes.MountNamespaceDriftProbe
import com.eltavine.duckdetector.features.nativeroot.data.probes.RootProcessAuditProbe
import com.eltavine.duckdetector.features.nativeroot.data.probes.SrcuTimingProbe
import com.eltavine.duckdetector.features.nativeroot.data.probes.ShellTmpMetadataProbe
import com.eltavine.duckdetector.features.nativeroot.data.probes.TempRootArtifactProbe
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootStage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class NativeRootRepository(
    context: Context? = null,
    private val nativeBridge: NativeRootNativeBridge = NativeRootNativeBridge(),
    private val shellTmpMetadataProbe: ShellTmpMetadataProbe = ShellTmpMetadataProbe(),
    private val rootProcessAuditProbe: RootProcessAuditProbe = RootProcessAuditProbe(),
    private val cgroupProcessLeakProbe: CgroupProcessLeakProbe = CgroupProcessLeakProbe(),
    private val mountNamespaceDriftProbe: MountNamespaceDriftProbe = MountNamespaceDriftProbe(
        context?.applicationContext
    ),
    private val kernelSuManagerFingerprintProbe: KernelSuManagerFingerprintProbe =
        KernelSuManagerFingerprintProbe(context?.applicationContext),
    private val tempRootArtifactProbe: TempRootArtifactProbe = TempRootArtifactProbe(),
    private val throneHuntRound: KernelSuThroneHuntRound = KernelSuThroneHuntRound(
        context?.applicationContext
    ),
    private val throneHuntProbe: KernelSuThroneHuntProbe = KernelSuThroneHuntProbe(),
    private val srcuTimingProbe: SrcuTimingProbe = SrcuTimingProbe(context?.applicationContext),
) : DetectorScanner<NativeRootReport> {

    override suspend fun scan(): NativeRootReport = withContext(Dispatchers.IO) {
        try {
            scanInternal()
        } catch (throwable: Throwable) {
            NativeRootReport.failed(throwable.message ?: "Native Root scan failed.")
        }
    }

    internal suspend fun scanInternal(): NativeRootReport {
        val scanStartedAt = SystemClock.elapsedRealtime()
        val snapshot = nativeBridge.collectSnapshot()
        val nativeFindings = snapshot.findings.mapIndexed { index, finding ->
            finding.toDomainFinding(index)
        }
        val shellTmpResult = shellTmpMetadataProbe.run()
        val rootProcessResult = rootProcessAuditProbe.run()
        val cgroupResult = cgroupProcessLeakProbe.run()
        val mountNamespaceResult = mountNamespaceDriftProbe.run()
        val managerFingerprintResult = kernelSuManagerFingerprintProbe.run()
        val tempRootArtifactResult = tempRootArtifactProbe.run()
        // Both stimuli run last, serially. The timing experiment precedes the asynchronous MIME
        // rewrite so this detector cannot introduce its own delayed write into the idle controls.
        val srcuTiming = srcuTimingProbe.collect()
        val throneHuntRoundResult = throneHuntRound.run(scanStartedAt)
        val throneHuntResult = throneHuntProbe.run(throneHuntRoundResult)
        val findings =
            nativeFindings +
                    shellTmpResult.findings +
                    rootProcessResult.findings +
                    cgroupResult.findings +
                    mountNamespaceResult.findings +
                    managerFingerprintResult.findings +
                    tempRootArtifactResult.findings +
                    throneHuntResult.findings

        return NativeRootReport(
            stage = NativeRootStage.READY,
            srcuTiming = srcuTiming,
            findings = findings,
            rootDetected = snapshot.rootDetected,
            kernelSuDetected = snapshot.kernelSuDetected,
            aPatchDetected = snapshot.aPatchDetected,
            magiskDetected = snapshot.magiskDetected,
            susfsDetected = snapshot.susfsDetected,
            kernelSuVersion = snapshot.kernelSuVersion,
            nativeAvailable = snapshot.available,
            prctlProbeHit = snapshot.prctlProbeHit,
            susfsProbeHit = snapshot.susfsProbeHit,
            pathHitCount = snapshot.pathHitCount + shellTmpResult.hitCount,
            pathCheckCount = snapshot.pathCheckCount + shellTmpResult.checkedCount,
            pathDeniedCount = snapshot.pathDeniedCount,
            processHitCount = snapshot.processHitCount + rootProcessResult.hitCount,
            processCheckedCount = snapshot.processCheckedCount + rootProcessResult.checkedCount,
            processDeniedCount = snapshot.processDeniedCount + rootProcessResult.deniedCount,
            cgroupAvailable = cgroupResult.available,
            cgroupPathCheckCount = cgroupResult.pathCheckCount,
            cgroupAccessiblePathCount = cgroupResult.accessiblePathCount,
            cgroupProcessCheckedCount = cgroupResult.processCheckedCount,
            cgroupProcDeniedCount = cgroupResult.procDeniedCount,
            cgroupHitCount = cgroupResult.hitCount,
            kernelHitCount = snapshot.kernelHitCount,
            kernelSourceCount = snapshot.kernelSourceCount,
            propertyHitCount = snapshot.propertyHitCount,
            propertyCheckCount = snapshot.propertyCheckCount,
            methods = buildMethods(
                snapshot = snapshot,
                findings = findings,
                shellTmpDetail = shellTmpResult.detail,
                rootProcessDetail = rootProcessResult.detail,
                cgroupResult = cgroupResult,
                mountNamespaceResult = mountNamespaceResult,
                managerFingerprintResult = managerFingerprintResult,
                tempRootArtifactResult = tempRootArtifactResult,
                throneHuntResult = throneHuntResult,
            ),
            kernelPatchSideChannel = snapshot.kernelPatchSideChannel,
            kernelPatchSuperkey = snapshot.kernelPatchSuperkey,
            kernelPatchSuperkeyAvailable = snapshot.kernelPatchSuperkeyAvailable,
            kernelPatchSuperkeyCheckedCount = snapshot.kernelPatchSuperkeyCheckedCount,
            kernelPatchSuperkeyHitCount = snapshot.kernelPatchSuperkeyHitCount,
            kernelPatchSuperkeyDetail = snapshot.kernelPatchSuperkeyDetail,
            ksuSupercallAttempted = snapshot.ksuSupercallAttempted,
            ksuSupercallProbeHit = snapshot.ksuSupercallProbeHit,
            ksuSupercallBlocked = snapshot.ksuSupercallBlocked,
            ksuSupercallSafeMode = snapshot.ksuSupercallSafeMode,
            ksuSupercallLkm = snapshot.ksuSupercallLkm,
            ksuSupercallLateLoad = snapshot.ksuSupercallLateLoad,
            ksuSupercallPrBuild = snapshot.ksuSupercallPrBuild,
            ksuSupercallManager = snapshot.ksuSupercallManager,
            selfSuDomain = snapshot.selfSuDomain,
            selfContext = snapshot.selfContext,
            selfKsuDriverFdCount = snapshot.selfKsuDriverFdCount,
            selfKsuFdwrapperFdCount = snapshot.selfKsuFdwrapperFdCount,
            isolatedMountProbeAvailable = mountNamespaceResult.isolatedProcessAvailable,
            mainMountNamespaceInode = mountNamespaceResult.mainNamespaceInode,
            isolatedMountNamespaceInode = mountNamespaceResult.isolatedNamespaceInode,
            mountDriftSignalCount = mountNamespaceResult.signalCount,
            mountAnchorDriftCount = mountNamespaceResult.mountAnchorDriftCount,
            ksuManagerPackagePresent = managerFingerprintResult.packagePresent,
            ksuManagerTraitHitCount = managerFingerprintResult.traitHitCount,
            ksuManagerVisibilityRestricted = managerFingerprintResult.visibilityRestricted,
            ksuManagerVisibilityUnknown = managerFingerprintResult.visibilityUnknown,
            tempRootDetected = tempRootArtifactResult.tempRootDetected,
            tempRootCveExploitDetected = tempRootArtifactResult.cveExploitDetected,
            tempRootArtifactHitCount = tempRootArtifactResult.hitCount,
            tempRootArtifactCheckCount = tempRootArtifactResult.checkedCount,
            ksuThroneHuntAvailable = throneHuntResult.available,
            ksuThroneHuntWatchDenied = throneHuntResult.watchDenied,
            ksuThroneHuntPackageDirectory = throneHuntResult.packageDirectory,
            ksuThroneHuntOpenCount = throneHuntResult.directoryOpenCount,
            ksuThroneHuntAccessCount = throneHuntResult.directoryAccessCount,
            ksuThroneHuntStimulusApplied = throneHuntRoundResult.stimulusApplied,
            ksuThroneHuntCollectionOutcome = throneHuntResult.collection.outcome.name,
            ksuThroneHuntCollectionDetail = throneHuntResult.collection.detail,
            ksuThroneHuntFailureStage = throneHuntResult.failureStage,
            ksuThroneHuntBaselineHitCount = throneHuntResult.baselineHitCount,
            ksuThroneHuntRawEventCount = throneHuntResult.rawEventCount,
            ksuThroneHuntInvalidEventCount = throneHuntResult.invalidEventCount,
            ksuThroneHuntWatchDescriptor = throneHuntResult.watchDescriptor,
            ksuThroneHuntStimulusDetail = throneHuntResult.stimulusDetail,
            ksuThroneHuntDiagnosticDetail = throneHuntResult.detail,
        )
    }

    private fun NativeRootNativeFinding.toDomainFinding(
        index: Int,
    ): NativeRootFinding {
        return NativeRootFinding(
            id = "${group.lowercase()}_$index",
            label = label,
            value = value,
            detail = detail,
            group = groupFromRaw(group),
            severity = severityFromRaw(severity),
            detailMonospace = true,
        )
    }

    private fun groupFromRaw(
        raw: String,
    ): NativeRootGroup {
        return when (raw) {
            "SYSCALL" -> NativeRootGroup.SYSCALL
            "SIDE_CHANNEL" -> NativeRootGroup.SIDE_CHANNEL
            "PATH" -> NativeRootGroup.PATH
            "PROCESS" -> NativeRootGroup.PROCESS
            "PACKAGE" -> NativeRootGroup.PACKAGE
            "KERNEL" -> NativeRootGroup.KERNEL
            "PROPERTY" -> NativeRootGroup.PROPERTY
            else -> NativeRootGroup.KERNEL
        }
    }

    private fun severityFromRaw(
        raw: String,
    ): NativeRootFindingSeverity {
        return when (raw) {
            "DANGER" -> NativeRootFindingSeverity.DANGER
            "WARNING" -> NativeRootFindingSeverity.WARNING
            else -> NativeRootFindingSeverity.INFO
        }
    }
}
