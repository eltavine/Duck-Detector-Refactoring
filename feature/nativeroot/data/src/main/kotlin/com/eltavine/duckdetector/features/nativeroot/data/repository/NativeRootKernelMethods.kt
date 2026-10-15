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

import com.eltavine.duckdetector.features.nativeroot.data.native.SusfsProbeOutcome
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethod
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodOutcome
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodResult

/**
 * The method rows of the probes that ask the kernel directly: supercalls, the KernelPatch
 * superkey, permission boundaries, prctl, SUSFS and this process's own indicators.
 */
internal fun NativeRootMethodEvidence.kernelInterfaceMethods(): List<NativeRootMethodResult> = listOf(
    NativeRootMethodResult(
        method = NativeRootMethod.KSU_READONLY_SUPERCALL,
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
        method = NativeRootMethod.NR_SUPERCALL_PROBE,
        summary = when {
            !snapshot.kernelPatchSideChannelAvailable -> "Unavailable"
            snapshot.kernelPatchSideChannel -> "Elevated ratio"
            else -> "Ratio below threshold"
        },
        outcome = NativeRootMethodOutcome.SUPPORT,
        detail = buildString {
            append("Times arm64 syscall 45 with a 128-byte key and an empty key, and reports the full/empty ratio. ")
            append("KernelPatch commit 84169d5d6be12e589ccac81d71dcebb80b22043a reported ratios of approximately 9.3 before its fix, 1.6 after it, and 1.8 without KernelPatch; an additional reported device measured 1.94.\n")
            append("The 3.0 threshold is provisional. A ratio cancels common multiplicative scaling, but not additive syscall overhead or differences in path lookup. Cross-device detection accuracy has not been established.\n")
            append("An elevated ratio is supporting timing evidence only and does not identify APatch or KernelPatch. A lower ratio cannot exclude the older leak or KernelPatch itself. The separate superkey probe retains its own applicability limits.\n")
            append("Test Result: ${snapshot.kernelPatchSideChannelDetail}")
        },
    ),
    NativeRootMethodResult(
        method = NativeRootMethod.KERNELPATCH_SUPERKEY,
        summary = when {
            snapshot.kernelPatchSuperkey -> "Detected"
            !snapshot.kernelPatchSuperkeyAvailable -> "Unavailable"
            else -> "Clean"
        },
        outcome = when {
            snapshot.kernelPatchSuperkey -> NativeRootMethodOutcome.DETECTED
            !snapshot.kernelPatchSuperkeyAvailable -> NativeRootMethodOutcome.SUPPORT
            else -> NativeRootMethodOutcome.CLEAN
        },
        detail = buildString {
            append("Passes __NR_supercall an untouched anonymous page together with a length the kernel rejects before it derives a user pointer, ")
            append("so a stock kernel never reads arg0 and the page keeps its empty PTE.\n")
            append("KernelPatch reads arg0 to compare it against the superkey ahead of the syscall body, which faults the page in; mincore then reports it resident.\n")
            append("This is a state check, so it does not depend on timing or CPU frequency.\n")
            append("A positive residency hit is conclusive on any kernel version, but a negative result is only treated as Clean inside the probe's conservative faulting-uaccess scope (kernel <= 6.6). Kernel 6.7+, or an unparseable kernel release, is reported as Unavailable instead of turning a known nofault blind spot into a false Clean verdict.\n")
            append("A run with a failed page mapping, no control page, a resident control page, a pre-resident attempt, an incomplete attempt set, or a failed residency read is also reported as Unavailable rather than Clean.\n")
            append("Test Result: ${snapshot.kernelPatchSuperkeyDetail}")
        },
    ),
    NativeRootMethodResult(
        method = NativeRootMethod.DEVPTS_PERMISSION_CHECK,
        summary = when {
            snapshot.devptsAbnormalPermission -> "Detected"
            snapshot.devptsAbnormalPermissionCheckedCount == 0 -> "Unavailable"
            !snapshot.devptsAbnormalPermissionAvailable -> "Limited"
            else -> "Clean"
        },
        outcome = when {
            snapshot.devptsAbnormalPermission -> NativeRootMethodOutcome.DETECTED
            snapshot.devptsAbnormalPermissionCheckedCount == 0 -> NativeRootMethodOutcome.SUPPORT
            !snapshot.devptsAbnormalPermissionAvailable -> NativeRootMethodOutcome.SUPPORT
            else -> NativeRootMethodOutcome.CLEAN
        },
        detail = buildString {
            append("Checks /dev/pts owner uid and SELinux labels from existing PTYs plus a freshly created PTY.")
            append("\nIn a normal system, the probe should not find uid 0 PTYs or a u:object_r:ksu_file:s0 label.")
            if (!snapshot.devptsAbnormalPermission) {
                when {
                    snapshot.devptsAbnormalPermissionCheckedCount == 0 ->
                        append("\nNo usable PTY sample was collected, so this probe stayed unavailable.")

                    !snapshot.devptsAbnormalPermissionAvailable ->
                        append("\nThe probe ran, but coverage was partial, so this result stays support-only.")
                }
            }
            append("\nTest Result: \n")
            append(snapshot.devptsAbnormalPermissionDetail)
        },
    ),
    NativeRootMethodResult(
        method = NativeRootMethod.PERMISSION_BOUNDARY_CHECK,
        summary = when {
            snapshot.permissionBoundaryDetected -> "Detected"
            !snapshot.permissionBoundaryAvailable -> "Unavailable"
            else -> "Clean"
        },
        outcome = when {
            snapshot.permissionBoundaryDetected -> NativeRootMethodOutcome.DETECTED
            !snapshot.permissionBoundaryAvailable -> NativeRootMethodOutcome.SUPPORT
            else -> NativeRootMethodOutcome.CLEAN
        },
        detail = buildString {
            append("Checks SELinux's netlink boundaries for RTM_GETLINK and RTM_GETNEIGH.")
            append("\nAOSP policy denies RTM_GETLINK to apps targeting SDK 30 or later on Android 11 and 12 and to every app from Android 13, and denies RTM_GETNEIGH from Android 13 to apps targeting SDK 32 or later; CTS checks both. Where a denial does not apply to this process, that check is not applicable.")
            append("\nAn answered request that exposes a physical MAC or a LAN neighbour shows SELinux did not enforce the denial, which modified policy, a permissive domain or a kernel without Android's netlink patches can cause.")
            append("\nTest Result:\n")
            append(snapshot.permissionBoundaryDetail)
        },
    ),
    NativeRootMethodResult(
        method = NativeRootMethod.PRCTL_PROBE,
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
        method = NativeRootMethod.SUSFS_SIDE_CHANNEL,
        summary = when (snapshot.susfsProbeOutcome) {
            SusfsProbeOutcome.KILLED -> "SIGKILL"
            SusfsProbeOutcome.CHANGED_UID -> "UID changed"
            SusfsProbeOutcome.DENIED -> "Normal"
            SusfsProbeOutcome.NOT_OBSERVED -> "Unavailable"
        },
        outcome = when (snapshot.susfsProbeOutcome) {
            SusfsProbeOutcome.KILLED, SusfsProbeOutcome.CHANGED_UID -> NativeRootMethodOutcome.DETECTED
            SusfsProbeOutcome.DENIED -> NativeRootMethodOutcome.CLEAN
            SusfsProbeOutcome.NOT_OBSERVED -> NativeRootMethodOutcome.SUPPORT
        },
        detail = buildString {
            append("Fork child and attempt setresuid to a lower UID. Old SUSFS/KSU hooks can kill the child instead of returning EPERM.")
            if (snapshot.susfsProbeDetail.isNotBlank()) {
                append("\nTest Result: ")
                append(snapshot.susfsProbeDetail)
            }
        },
    ),
    NativeRootMethodResult(
        method = NativeRootMethod.SUSFS_GETDENTS_RACE,
        summary = when {
            snapshot.susfsGetdentsRaceDetected -> "Leaked"
            snapshot.susfsGetdentsRaceAvailable -> "Clean"
            else -> "Unavailable"
        },
        outcome = when {
            snapshot.susfsGetdentsRaceDetected -> NativeRootMethodOutcome.DETECTED
            snapshot.susfsGetdentsRaceAvailable -> NativeRootMethodOutcome.CLEAN
            else -> NativeRootMethodOutcome.SUPPORT
        },
        detail = buildString {
            append("Race getdents64(/proc) against a toggler thread that flips the buffer to PROT_NONE mid-syscall. ")
            append("The susfs4ksu-lkm filter bails out on the fault and returns the ORIGINAL unfiltered buffer, so hidden names survive.")
            if (snapshot.susfsGetdentsRaceDetail.isNotBlank()) {
                append("\nTest Result: ")
                append(snapshot.susfsGetdentsRaceDetail)
            }
        },
    ),
    NativeRootMethodResult(
        method = NativeRootMethod.SUSFS_OPATH_CONSISTENCY,
        summary = when {
            snapshot.susfsOpathConsistencyDetected -> "Inconsistent"
            snapshot.susfsOpathConsistencyAvailable -> "Consistent"
            else -> "Unavailable"
        },
        outcome = when {
            snapshot.susfsOpathConsistencyDetected -> NativeRootMethodOutcome.DETECTED
            snapshot.susfsOpathConsistencyAvailable -> NativeRootMethodOutcome.CLEAN
            else -> NativeRootMethodOutcome.SUPPORT
        },
        detail = buildString {
            append("Check the /proc/susfs_* control nodes through stat(), open(O_PATH) and fstat(). ")
            append("A genuine proc entry cannot answer ENOENT on one interface after resolving on another - that mismatch is the susfs4ksu-lkm interception signature.")
            if (snapshot.susfsOpathConsistencyDetail.isNotBlank()) {
                append("\nTest Result: ")
                append(snapshot.susfsOpathConsistencyDetail)
            }
        },
    ),
    NativeRootMethodResult(
        method = NativeRootMethod.SELF_PROCESS_IOC,
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
)
