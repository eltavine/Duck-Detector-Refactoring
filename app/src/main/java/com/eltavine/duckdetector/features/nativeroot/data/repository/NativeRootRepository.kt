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

package com.eltavine.duckdetector.features.nativeroot.data.repository

import android.content.Context
import com.eltavine.duckdetector.features.nativeroot.data.native.NativeRootNativeBridge
import com.eltavine.duckdetector.features.nativeroot.data.native.NativeRootNativeFinding
import com.eltavine.duckdetector.features.nativeroot.data.native.NativeRootNativeSnapshot
import com.eltavine.duckdetector.features.nativeroot.data.probes.CgroupProcessLeakProbe
import com.eltavine.duckdetector.features.nativeroot.data.probes.CgroupProcessLeakProbeResult
import com.eltavine.duckdetector.features.nativeroot.data.probes.KernelSuManagerFingerprintProbe
import com.eltavine.duckdetector.features.nativeroot.data.probes.KernelSuManagerFingerprintProbeResult
import com.eltavine.duckdetector.features.nativeroot.data.probes.MountNamespaceDriftProbe
import com.eltavine.duckdetector.features.nativeroot.data.probes.MountNamespaceDriftProbeResult
import com.eltavine.duckdetector.features.nativeroot.data.probes.RootProcessAuditProbe
import com.eltavine.duckdetector.features.nativeroot.data.probes.ShellTmpMetadataProbe
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodOutcome
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodResult
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
) {

    suspend fun scan(): NativeRootReport = withContext(Dispatchers.IO) {
        try {
            scanInternal()
        } catch (throwable: Throwable) {
            NativeRootReport.failed(throwable.message ?: "Native Root scan failed.")
        }
    }

    internal suspend fun scanInternal(): NativeRootReport {
        val snapshot = nativeBridge.collectSnapshot()
        val nativeFindings = snapshot.findings.mapIndexed { index, finding ->
            finding.toDomainFinding(index)
        }
        val shellTmpResult = shellTmpMetadataProbe.run()
        val rootProcessResult = rootProcessAuditProbe.run()
        val cgroupResult = cgroupProcessLeakProbe.run()
        val mountNamespaceResult = mountNamespaceDriftProbe.run()
        val managerFingerprintResult = kernelSuManagerFingerprintProbe.run()
        val findings =
            nativeFindings +
                    shellTmpResult.findings +
                    rootProcessResult.findings +
                    cgroupResult.findings +
                    mountNamespaceResult.findings +
                    managerFingerprintResult.findings

        return NativeRootReport(
            stage = NativeRootStage.READY,
            findings = findings,
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
            ),
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
        )
    }

    private fun buildMethods(
        snapshot: NativeRootNativeSnapshot,
        findings: List<NativeRootFinding>,
        shellTmpDetail: String,
        rootProcessDetail: String,
        cgroupResult: CgroupProcessLeakProbeResult,
        mountNamespaceResult: MountNamespaceDriftProbeResult,
        managerFingerprintResult: KernelSuManagerFingerprintProbeResult,
    ): List<NativeRootMethodResult> {
        val directFindings =
            findings.filter { it.group == NativeRootGroup.SYSCALL || it.group == NativeRootGroup.SIDE_CHANNEL }
        val runtimeFindings =
            findings.filter {
                it.group == NativeRootGroup.PATH ||
                        it.group == NativeRootGroup.PROCESS ||
                        it.group == NativeRootGroup.PACKAGE
            }
        val kernelFindings = findings.filter { it.group == NativeRootGroup.KERNEL }
        val propertyFindings = findings.filter { it.group == NativeRootGroup.PROPERTY }

        return listOf(
            NativeRootMethodResult(
                label = "ksuReadonlySupercall",
                summary = when {
                    snapshot.ksuSupercallProbeHit && snapshot.kernelSuVersion > 0L -> "v${snapshot.kernelSuVersion}"
                    snapshot.ksuSupercallProbeHit -> "Detected"
                    snapshot.ksuSupercallBlocked -> "Blocked"
                    snapshot.ksuSupercallAttempted -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    snapshot.ksuSupercallProbeHit -> NativeRootMethodOutcome.DETECTED
                    snapshot.ksuSupercallBlocked -> NativeRootMethodOutcome.SUPPORT
                    snapshot.ksuSupercallAttempted -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = buildString {
                    append("Uses a sacrificial child process to request a temporary [ksu_driver] fd through the KernelSU reboot-magic install path, then calls GET_INFO and CHECK_SAFEMODE without manager/root privileges.")
                    if (snapshot.ksuSupercallBlocked) {
                        append("\nThe device seccomp policy trapped reboot() for the helper process before a [ksu_driver] fd could be installed.")
                    } else if (snapshot.ksuSupercallProbeHit) {
                        append("\nFlags:")
                        append(if (snapshot.ksuSupercallLkm) " LKM" else " non-LKM")
                        append(if (snapshot.ksuSupercallLateLoad) ", late-load" else ", early-load")
                        if (snapshot.ksuSupercallPrBuild) {
                            append(", PR build")
                        }
                        if (snapshot.ksuSupercallManager) {
                            append(", manager context")
                        }
                        append("\nSafe mode: ")
                        append(if (snapshot.ksuSupercallSafeMode) "enabled" else "disabled")
                    } else if (!snapshot.ksuSupercallAttempted) {
                        append("\nThe helper process did not return a valid result, so this direct probe stayed unavailable.")
                    }
                },
            ),
            NativeRootMethodResult(
                label = "prctlProbe",
                summary = when {
                    snapshot.prctlProbeHit && snapshot.kernelSuVersion > 0L -> "v${snapshot.kernelSuVersion}"
                    snapshot.prctlProbeHit -> "Detected"
                    snapshot.available -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    snapshot.prctlProbeHit -> NativeRootMethodOutcome.DETECTED
                    snapshot.available -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = "KernelSU magic prctl probe using option 0xDEADBEEF.",
            ),
            NativeRootMethodResult(
                label = "susfsSideChannel",
                summary = when {
                    snapshot.susfsProbeHit -> "SIGKILL"
                    snapshot.available -> "Normal"
                    else -> "Unavailable"
                },
                outcome = when {
                    snapshot.susfsProbeHit -> NativeRootMethodOutcome.DETECTED
                    snapshot.available -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = "Fork child and attempt setresuid to a lower UID. Old SUSFS/KSU hooks can kill the child instead of returning EPERM.",
            ),
            NativeRootMethodResult(
                label = "selfProcessIoc",
                summary = when {
                    snapshot.selfSuDomain -> "su domain"
                    snapshot.selfKsuDriverFdCount + snapshot.selfKsuFdwrapperFdCount > 0 -> "FD residue"
                    snapshot.selfContext.isNotBlank() -> "Normal"
                    snapshot.available -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    snapshot.selfSuDomain ||
                            snapshot.selfKsuDriverFdCount + snapshot.selfKsuFdwrapperFdCount > 0 ->
                        NativeRootMethodOutcome.DETECTED

                    snapshot.available -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = buildString {
                    append("Checks whether the current app process already runs in the KernelSU su SELinux domain or holds ambient [ksu_driver]/[ksu_fdwrapper] descriptors before escalation.")
                    if (snapshot.selfContext.isNotBlank()) {
                        append("\nContext: ")
                        append(snapshot.selfContext)
                    }
                    append("\nDriver FDs: ")
                    append(snapshot.selfKsuDriverFdCount)
                    append("\nFD wrapper FDs: ")
                    append(snapshot.selfKsuFdwrapperFdCount)
                },
            ),
            NativeRootMethodResult(
                label = "isolatedMountDrift",
                summary = when {
                    mountNamespaceResult.signalCount > 0 && mountNamespaceResult.mountAnchorDriftCount > 0 ->
                        "${mountNamespaceResult.mountAnchorDriftCount} anchor(s)"

                    mountNamespaceResult.signalCount > 0 -> "${mountNamespaceResult.signalCount} drift hit(s)"
                    mountNamespaceResult.isolatedProcessAvailable -> "Clean"
                    mountNamespaceResult.available -> "Unavailable"
                    else -> "Unavailable"
                },
                outcome = when {
                    mountNamespaceResult.signalCount > 0 -> NativeRootMethodOutcome.WARNING
                    mountNamespaceResult.isolatedProcessAvailable -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = buildString {
                    append("Compares the main app process against an isolated helper process using /proc/self/ns/mnt plus /apex, /system, and /vendor mount anchors. This is an ordinary-app-safe way to look for KSU profile mount namespace drift.")
                    if (mountNamespaceResult.detail.isNotBlank()) {
                        append("\n")
                        append(mountNamespaceResult.detail)
                    }
                },
            ),
            NativeRootMethodResult(
                label = "ksuManagerFingerprint",
                summary = when {
                    managerFingerprintResult.packagePresent && managerFingerprintResult.traitHitCount > 0 ->
                        "${managerFingerprintResult.traitHitCount}/3 traits"

                    managerFingerprintResult.packagePresent -> "Present"
                    managerFingerprintResult.visibilityRestricted -> "Scoped"
                    managerFingerprintResult.available -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    managerFingerprintResult.packagePresent -> NativeRootMethodOutcome.WARNING
                    managerFingerprintResult.visibilityRestricted -> NativeRootMethodOutcome.SUPPORT
                    managerFingerprintResult.available -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = buildString {
                    append("Reads the public manager manifest for zygotePreloadName, isolatedProcess, and useAppZygote traits under the well-known KernelSU package name. This is auxiliary only because package visibility, repackaging, or renamed managers can change it.")
                    if (managerFingerprintResult.detail.isNotBlank()) {
                        append("\n")
                        append(managerFingerprintResult.detail)
                    }
                },
            ),
            NativeRootMethodResult(
                label = "runtimeArtifacts",
                summary = when {
                    runtimeFindings.isNotEmpty() -> "${runtimeFindings.size} hit(s)"
                    snapshot.available -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    runtimeFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> NativeRootMethodOutcome.DETECTED
                    runtimeFindings.isNotEmpty() -> NativeRootMethodOutcome.WARNING
                    snapshot.available -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = buildString {
                    append("Scan /data/adb manager paths, curated tmp/system/storage residue paths, /data/local/tmp metadata, /proc process state, per-UID cgroup trees, isolated-process mount drift, and weak KernelSU manager manifest fingerprints for KernelSU, APatch, KernelPatch, Magisk, selective hiding, and unexpected root-process traces.")
                    if (shellTmpDetail.isNotBlank()) {
                        append("\nShell tmp: ")
                        append(shellTmpDetail)
                    }
                    if (rootProcessDetail.isNotBlank()) {
                        append("\nProcess audit: ")
                        append(rootProcessDetail)
                    }
                    if (cgroupResult.detail.isNotBlank()) {
                        append("\nCgroup audit: ")
                        append(cgroupResult.detail)
                    }
                    if (mountNamespaceResult.detail.isNotBlank()) {
                        append("\nMount drift: ")
                        append(mountNamespaceResult.detail)
                    }
                    if (managerFingerprintResult.detail.isNotBlank()) {
                        append("\nManager fingerprint: ")
                        append(managerFingerprintResult.detail)
                    }
                },
            ),
            NativeRootMethodResult(
                label = "cgroupLeakage",
                summary = when {
                    cgroupResult.hitCount > 0 -> "${cgroupResult.hitCount} hit(s)"
                    cgroupResult.available -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    cgroupResult.findings.any { it.severity == NativeRootFindingSeverity.DANGER } -> NativeRootMethodOutcome.DETECTED
                    cgroupResult.hitCount > 0 -> NativeRootMethodOutcome.WARNING
                    cgroupResult.available -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = "Enumerate per-UID cgroup trees and compare native getdents visibility against Java File view, /proc/<pid>/status UID ownership, and PID liveness syscalls such as kill/getsid/getpgid/sched_getscheduler/pidfd_open. ${cgroupResult.detail}".trim(),
            ),
            NativeRootMethodResult(
                label = "kernelTraces",
                summary = when {
                    kernelFindings.isNotEmpty() -> "${kernelFindings.size} source(s)"
                    snapshot.available -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    kernelFindings.isNotEmpty() -> NativeRootMethodOutcome.WARNING
                    snapshot.available -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = "Check /proc/kallsyms, /proc/modules, and uname strings for KernelSU, APatch, KernelPatch, SuperCall, or Magisk tokens.",
            ),
            NativeRootMethodResult(
                label = "propertyResidue",
                summary = when {
                    propertyFindings.isNotEmpty() -> "${propertyFindings.size} hit(s)"
                    snapshot.available -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    propertyFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> NativeRootMethodOutcome.DETECTED
                    propertyFindings.isNotEmpty() -> NativeRootMethodOutcome.WARNING
                    snapshot.available -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = "Read a small catalog of root-specific properties such as ro.kernel.ksu and APatch/KernelPatch variants.",
            ),
            NativeRootMethodResult(
                label = "nativeLibrary",
                summary = if (snapshot.available) "Loaded" else "Unavailable",
                outcome = if (snapshot.available) NativeRootMethodOutcome.CLEAN else NativeRootMethodOutcome.SUPPORT,
                detail = "JNI-backed native root detection module.",
            ),
            NativeRootMethodResult(
                label = "signalSummary",
                summary = when {
                    directFindings.isNotEmpty() -> "${directFindings.size} direct"
                    findings.isNotEmpty() -> "${findings.size} indirect"
                    snapshot.available -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    directFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> NativeRootMethodOutcome.DETECTED
                    findings.isNotEmpty() -> NativeRootMethodOutcome.WARNING
                    snapshot.available -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = "Direct probes are syscall and side-channel results; indirect probes are kernel strings, paths, processes, properties, and cgroup leakage.",
            ),
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
