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

import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethod
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodOutcome
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodResult

/**
 * The method rows of the namespace, manager and artifact probes, the native library and the signal
 * summary.
 */
internal fun NativeRootMethodEvidence.namespaceAndArtifactMethods(): List<NativeRootMethodResult> = listOf(
    NativeRootMethodResult(
        method = NativeRootMethod.ISOLATED_MOUNT_DRIFT,
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
        method = NativeRootMethod.KSU_MANAGER_FINGERPRINT,
        summary = when {
            managerFingerprintResult.packagePresent && managerFingerprintResult.traitHitCount > 0 ->
                "${managerFingerprintResult.traitHitCount}/3 traits"

            managerFingerprintResult.packagePresent -> "Present"
            managerFingerprintResult.visibilityRestricted -> "Scoped"
            managerFingerprintResult.visibilityUnknown -> "Unavailable"
            managerFingerprintResult.available -> "Clean"
            else -> "Unavailable"
        },
        outcome = when {
            managerFingerprintResult.packagePresent -> NativeRootMethodOutcome.WARNING
            managerFingerprintResult.visibilityRestricted || managerFingerprintResult.visibilityUnknown ->
                NativeRootMethodOutcome.SUPPORT
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
        method = NativeRootMethod.KSU_THRONE_HUNT,
        summary = when {
            throneHuntResult.watchDenied -> "Watch denied"
            !throneHuntResult.available -> throneHuntResult.failureStage
            throneHuntResult.hitCount > 0 -> "${throneHuntResult.hitCount} unattributed event(s)"
            else -> "No directory events"
        },
        outcome = NativeRootMethodOutcome.SUPPORT,
        detail = buildString {
            append("Requests a /data/system/packages.list rewrite through the zero-permission setMimeGroup path ")
            append("and watches the app's own /data/app package directory from the app_zygote carrier. ")
            append("IN_OPEN/IN_ACCESS events have no accessor PID/UID and cannot identify KernelSU ")
            append("or search_manager. Event counts and timing do not establish attribution. ")
            append("FMODE_NONOTIFY can suppress these file notifications, so zero events cannot exclude ")
            append("a manager scan or KernelSU. These counters are diagnostic only.\n")
            append("collection=")
            append(throneHuntResult.collection.outcome.name)
            append("\nfailureStage=")
            append(throneHuntResult.failureStage)
            append("\nopen=")
            append(throneHuntResult.directoryOpenCount)
            append(" access=")
            append(throneHuntResult.directoryAccessCount)
            append(" raw=")
            append(throneHuntResult.rawEventCount)
            append(" invalid=")
            append(throneHuntResult.invalidEventCount)
            append(" baseline=")
            append(throneHuntResult.baselineHitCount)
            append("\nstimulus=")
            append(throneHuntResult.stimulusDetail)
            append('\n')
            if (throneHuntResult.detail.isNotBlank()) {
                append(throneHuntResult.detail)
            }
        },
    ),
    NativeRootMethodResult(
        method = NativeRootMethod.RUNTIME_ARTIFACTS,
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
        method = NativeRootMethod.CGROUP_LEAKAGE,
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
        method = NativeRootMethod.KERNEL_TRACES,
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
        method = NativeRootMethod.PROPERTY_RESIDUE,
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
        method = NativeRootMethod.TEMP_ROOT_ARTIFACTS,
        summary = when {
            tempRootArtifactResult.cveExploitDetected -> "CVE-2026-43499"
            tempRootArtifactResult.tempRootDetected -> "${tempRootArtifactResult.hitCount} hit(s)"
            tempRootArtifactResult.available -> "Clean"
            else -> "Unavailable"
        },
        outcome = when {
            tempRootArtifactResult.tempRootDetected -> NativeRootMethodOutcome.DETECTED
            tempRootArtifactResult.available -> NativeRootMethodOutcome.CLEAN
            else -> NativeRootMethodOutcome.SUPPORT
        },
        detail = "Scans /data/local/tmp for temp root exploit artifacts (ksud, temp_su, ksu-helper, ksu-payload, libcve43499root.so). Files matching the CVE-2026-43499 tooling show it was staged on this device; they do not show whether an escalation succeeded or is still active. Paths this process cannot stat leave the check unavailable.",
    ),
    NativeRootMethodResult(
        method = NativeRootMethod.NATIVE_LIBRARY,
        summary = if (snapshot.available) "Loaded" else "Unavailable",
        outcome = if (snapshot.available) NativeRootMethodOutcome.CLEAN else NativeRootMethodOutcome.SUPPORT,
        detail = "JNI-backed native root detection module.",
    ),
    NativeRootMethodResult(
        method = NativeRootMethod.SIGNAL_SUMMARY,
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
