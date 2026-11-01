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

package com.eltavine.duckdetector.features.selinux.data.repository

import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxContextValiditySnapshot
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxDirtyPolicyRuleClassification
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyRule
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyRuleSet
import com.eltavine.duckdetector.features.selinux.domain.SelinuxRuleVerdict

fun buildDirtyPolicyMethods(
    snapshot: SelinuxContextValiditySnapshot,
): List<SelinuxCheckResult> {
    val nativeTrack = dirtyPolicyTrack(snapshot, DirtyPolicyTrackSource.NATIVE)
    val javaTrack = dirtyPolicyTrack(snapshot, DirtyPolicyTrackSource.JAVA)
    return listOf(
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            edge = "system_server execmem",
            nativeAllowed = nativeTrack.systemServerExecmemAllowed,
            javaAllowed = javaTrack.systemServerExecmemAllowed,
            detail = "Observed edge: system_server -> system_server:process execmem. This should stay denied on stock policy because executable system_server memory is supporting dirty-policy evidence.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ),
        // A policy baseline difference cannot identify who introduced the rule. Keep the
        // oracle evidence, but do not turn either verdict into a security classification.
        // AOSP Android 14: https://android.googlesource.com/platform/system/sepolicy/+/refs/tags/android-14.0.0_r1/public/fsck_untrusted.te
        // ROM exception: https://github.com/LineageOS/android_system_sepolicy/commit/85839045447fee9db99258f66f9fa2c65473b10d
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.POLICY_OBSERVATION,
            edge = "fsck_untrusted sys_admin",
            nativeAllowed = nativeTrack.fsckSysAdminAllowed,
            javaAllowed = javaTrack.fsckSysAdminAllowed,
            detail = "Observed edge: fsck_untrusted -> fsck_untrusted:capability sys_admin. Informational only: AOSP Android 14 forbids this permission, but device or ROM policies may differ. An allowed result alone does not establish root or policy tampering and does not contribute to the dirty-policy warning.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ).copy(isSecure = null),
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            edge = "shell -> su transition",
            nativeAllowed = nativeTrack.shellSuTransitionAllowed,
            javaAllowed = javaTrack.shellSuTransitionAllowed,
            detail = "Observed edge: shell -> su:process transition. This is only evaluated for confirmed user builds because stock user builds should not expose an AOSP su transition path.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ),
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            edge = "adbd -> adbroot binder",
            nativeAllowed = nativeTrack.adbdAdbrootBinderCallAllowed,
            javaAllowed = javaTrack.adbdAdbrootBinderCallAllowed,
            detail = "Observed edge: adbd -> adbroot:binder call. This should stay denied on stock policy because it is supporting adb-root dirty-policy evidence.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ),
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            edge = "untrusted_app -> magisk binder",
            nativeAllowed = nativeTrack.magiskBinderCallAllowed,
            javaAllowed = javaTrack.magiskBinderCallAllowed,
            detail = "Observed edge: untrusted_app -> magisk:binder call. This should stay denied on stock policy because ordinary apps should not talk to a Magisk domain over binder.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ),
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            edge = "untrusted_app -> ksu_file read",
            nativeAllowed = nativeTrack.ksuFileReadAllowed,
            javaAllowed = javaTrack.ksuFileReadAllowed,
            detail = "Observed edge: untrusted_app -> ksu_file:file read. This should stay denied on stock policy because ordinary apps should not read KernelSU-labeled files.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ),
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            edge = "untrusted_app -> lsposed_file read",
            nativeAllowed = nativeTrack.lsposedFileReadAllowed,
            javaAllowed = javaTrack.lsposedFileReadAllowed,
            detail = "Observed edge: untrusted_app -> lsposed_file:file read. This should stay denied on stock policy because ordinary apps should not read LSPosed-labeled files.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ),
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.DROIDSPACES,
            edge = "magisk -> droidspacesd dyntransition",
            nativeAllowed = nativeTrack.magiskDroidspacesdTransitionAllowed,
            javaAllowed = javaTrack.magiskDroidspacesdTransitionAllowed,
            detail = "Observed edge: magisk -> droidspacesd:process dyntransition. Droidspaces seeds this transition from its module policy so Magisk-rooted execution can move into the dedicated droidspacesd domain.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ),
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.DROIDSPACES,
            edge = "su -> droidspacesd dyntransition",
            nativeAllowed = nativeTrack.suDroidspacesdTransitionAllowed,
            javaAllowed = javaTrack.suDroidspacesdTransitionAllowed,
            detail = "Observed edge: su -> droidspacesd:process dyntransition. Droidspaces exposes this transition so an su-rooted process can enter the dedicated droidspacesd domain.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ),
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.DROIDSPACES,
            edge = "system_server -> droidspacesd binder",
            nativeAllowed = nativeTrack.systemServerDroidspacesdBinderCallAllowed,
            javaAllowed = javaTrack.systemServerDroidspacesdBinderCallAllowed,
            detail = "Observed edge: system_server -> droidspacesd:binder call. Droidspaces allows system_server to talk to the dedicated droidspacesd service over binder.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ),
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.MSD,
            edge = "msd_app -> msd_daemon connectto",
            nativeAllowed = nativeTrack.msdAppDaemonConnectAllowed,
            javaAllowed = javaTrack.msdAppDaemonConnectAllowed,
            detail = "Observed edge: msd_app -> msd_daemon:unix_stream_socket connectto. MSD relies on this dedicated app/domain socket path to talk to its daemon.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ),
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.MSD,
            edge = "msd_daemon -> msd_daemon connectto",
            nativeAllowed = nativeTrack.msdDaemonSelfConnectAllowed,
            javaAllowed = javaTrack.msdDaemonSelfConnectAllowed,
            detail = "Observed edge: msd_daemon -> msd_daemon:unix_stream_socket connectto. MSD explicitly denies self-connect as a sanity check for its loaded policy shape.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ),
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.MSD,
            edge = "msd_daemon -> selinuxfs read",
            nativeAllowed = nativeTrack.msdDaemonSelinuxfsReadAllowed,
            javaAllowed = javaTrack.msdDaemonSelinuxfsReadAllowed,
            detail = "Observed edge: msd_daemon -> selinuxfs:file read. MSD's daemon uses this to verify enforcing SELinux state before accepting clients.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ),
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.MSD,
            edge = "msd_daemon -> configfs dir search",
            nativeAllowed = nativeTrack.msdDaemonConfigfsDirSearchAllowed,
            javaAllowed = javaTrack.msdDaemonConfigfsDirSearchAllowed,
            detail = "Observed edge: msd_daemon -> configfs:dir search. MSD's daemon needs this to traverse USB gadget configfs state.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ),
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.MSD,
            edge = "msd_daemon -> configfs file write",
            nativeAllowed = nativeTrack.msdDaemonConfigfsFileWriteAllowed,
            javaAllowed = javaTrack.msdDaemonConfigfsFileWriteAllowed,
            detail = "Observed edge: msd_daemon -> configfs:file write. MSD's daemon needs this to configure USB gadget mass-storage state.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ),
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            edge = "untrusted_app -> xposed_data read",
            nativeAllowed = nativeTrack.xposedDataFileReadAllowed,
            javaAllowed = javaTrack.xposedDataFileReadAllowed,
            detail = "Observed edge: untrusted_app -> xposed_data:file read. This should stay denied on stock policy because ordinary apps should not read Xposed data directly.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ),
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            edge = "zygote -> adb_data_file search",
            nativeAllowed = nativeTrack.zygoteAdbDataSearchAllowed,
            javaAllowed = javaTrack.zygoteAdbDataSearchAllowed,
            detail = "Observed edge: zygote -> adb_data_file:dir search. This should stay denied on stock policy because zygote should not traverse adb data directories.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ),
    ) + ADDITIONAL_DIRTY_POLICY_EDGES.map { edge ->
        aggregateDirtyPolicyRuleMethod(
            set = SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            edge = edge,
            nativeAllowed = nativeTrack.additionalRules[edge],
            javaAllowed = javaTrack.additionalRules[edge],
            detail = "Observed edge: $edge. DirtySepolicy 2.2 checks this access rule; an allowed edge alone cannot identify its origin.",
            nativeTrack = nativeTrack,
            javaTrack = javaTrack,
        ).copy(dirtySepolicyWarningOnly = true)
    }
}

private fun aggregateDirtyPolicyRuleMethod(
    set: SelinuxPolicyRuleSet,
    edge: String,
    nativeAllowed: Boolean?,
    javaAllowed: Boolean?,
    detail: String,
    nativeTrack: DirtyPolicyTrack,
    javaTrack: DirtyPolicyTrack,
): SelinuxCheckResult {
    val effectiveNativeAllowed = nativeAllowed.takeIf { nativeTrack.reportable }
    val effectiveJavaAllowed = javaAllowed.takeIf { javaTrack.reportable }
    val allowed = when {
        effectiveNativeAllowed != null && effectiveJavaAllowed != null && effectiveNativeAllowed != effectiveJavaAllowed -> null
        effectiveNativeAllowed == true || effectiveJavaAllowed == true -> true
        effectiveNativeAllowed == false || effectiveJavaAllowed == false -> false
        else -> null
    }
    val trusted = allowed == true && (
        nativeTrack.trusted && effectiveNativeAllowed == true ||
            javaTrack.trusted && effectiveJavaAllowed == true
        )
    val classification = if (SelinuxDirtyPolicyRuleClassification.isAlertEligible(edge)) set
        else SelinuxPolicyRuleSet.POLICY_OBSERVATION
    val rule = SelinuxPolicyRule(
        set = classification,
        edge = edge,
        verdict = when (allowed) {
            true -> SelinuxRuleVerdict.ALLOWED
            false -> SelinuxRuleVerdict.DENIED
            null -> SelinuxRuleVerdict.UNAVAILABLE
        },
    )
    return SelinuxCheckResult(
        method = rule.method,
        status = rule.verdict.label,
        isSecure = when (allowed) {
            null -> null
            else -> if (classification == SelinuxPolicyRuleSet.POLICY_OBSERVATION) null else !allowed
        },
        permissionDenied = false,
        details = buildList {
            add("Evidence source=${EvidenceSource.DEDICATED_CARRIER.label}")
            add(
                when (allowed) {
                    true -> "$detail The dedicated access oracles reported this edge as allowed."
                    false -> "$detail The dedicated access oracles reported this edge as denied."
                    null -> "$detail The dedicated access oracles could not produce a verdict for this edge."
                },
            )
            if (effectiveNativeAllowed != null && effectiveJavaAllowed != null && effectiveNativeAllowed != effectiveJavaAllowed) {
                add("The dedicated native and java app_zygote tracks disagreed on this edge, so the verdict was not trusted.")
            }
            add("Native dedicated=${nativeTrack.describe(nativeAllowed)}")
            add("Java dedicated=${javaTrack.describe(javaAllowed)}")
        }.joinToString(" | "),
        dirtyPolicyTrusted = trusted,
        policyRule = rule,
    )
}

private fun dirtyPolicyTrack(
    snapshot: SelinuxContextValiditySnapshot,
    source: DirtyPolicyTrackSource,
): DirtyPolicyTrack {
    return when (source) {
        DirtyPolicyTrackSource.NATIVE -> DirtyPolicyTrack(
            label = "native app_zygote",
            trusted = snapshot.dirtyPolicyTrusted,
            available = snapshot.dirtyPolicyAvailable,
            probeAttempted = snapshot.dirtyPolicyProbeAttempted,
            carrierContext = snapshot.dirtyPolicyCarrierContext,
            carrierMatchesExpected = snapshot.dirtyPolicyCarrierMatchesExpected,
            controlsPassed = snapshot.dirtyPolicyControlsPassed,
            stable = snapshot.dirtyPolicyStable,
            queryMethod = snapshot.dirtyPolicyQueryMethod,
            accessControlAllowed = snapshot.dirtyPolicyAccessControlAllowed,
            negativeControlRejected = snapshot.dirtyPolicyNegativeControlRejected,
            systemServerExecmemAllowed = snapshot.dirtyPolicySystemServerExecmemAllowed,
            fsckSysAdminAllowed = snapshot.dirtyPolicyFsckSysAdminAllowed,
            shellSuTransitionAllowed = snapshot.dirtyPolicyShellSuTransitionAllowed,
            adbdAdbrootBinderCallAllowed = snapshot.dirtyPolicyAdbdAdbrootBinderCallAllowed,
            magiskBinderCallAllowed = snapshot.dirtyPolicyMagiskBinderCallAllowed,
            ksuFileReadAllowed = snapshot.dirtyPolicyKsuFileReadAllowed,
            lsposedFileReadAllowed = snapshot.dirtyPolicyLsposedFileReadAllowed,
            magiskDroidspacesdTransitionAllowed = snapshot.dirtyPolicyMagiskDroidspacesdTransitionAllowed,
            suDroidspacesdTransitionAllowed = snapshot.dirtyPolicySuDroidspacesdTransitionAllowed,
            systemServerDroidspacesdBinderCallAllowed = snapshot.dirtyPolicySystemServerDroidspacesdBinderCallAllowed,
            msdAppDaemonConnectAllowed = snapshot.dirtyPolicyMsdAppDaemonConnectAllowed,
            msdDaemonSelfConnectAllowed = snapshot.dirtyPolicyMsdDaemonSelfConnectAllowed,
            msdDaemonSelinuxfsReadAllowed = snapshot.dirtyPolicyMsdDaemonSelinuxfsReadAllowed,
            msdDaemonConfigfsDirSearchAllowed = snapshot.dirtyPolicyMsdDaemonConfigfsDirSearchAllowed,
            msdDaemonConfigfsFileWriteAllowed = snapshot.dirtyPolicyMsdDaemonConfigfsFileWriteAllowed,
            xposedDataFileReadAllowed = snapshot.dirtyPolicyXposedDataFileReadAllowed,
            zygoteAdbDataSearchAllowed = snapshot.dirtyPolicyZygoteAdbDataSearchAllowed,
            failureReason = snapshot.dirtyPolicyFailureReason,
            additionalRules = snapshot.dirtyPolicyAdditionalRules,
        )
        DirtyPolicyTrackSource.JAVA -> DirtyPolicyTrack(
            label = "java app_zygote",
            trusted = snapshot.javaDirtyPolicyTrusted,
            available = snapshot.javaDirtyPolicyAvailable,
            probeAttempted = snapshot.javaDirtyPolicyProbeAttempted,
            carrierContext = snapshot.javaDirtyPolicyCarrierContext,
            carrierMatchesExpected = snapshot.javaDirtyPolicyCarrierMatchesExpected,
            controlsPassed = snapshot.javaDirtyPolicyControlsPassed,
            stable = snapshot.javaDirtyPolicyStable,
            queryMethod = snapshot.javaDirtyPolicyQueryMethod,
            accessControlAllowed = snapshot.javaDirtyPolicyAccessControlAllowed,
            negativeControlRejected = snapshot.javaDirtyPolicyNegativeControlRejected,
            systemServerExecmemAllowed = snapshot.javaDirtyPolicySystemServerExecmemAllowed,
            fsckSysAdminAllowed = snapshot.javaDirtyPolicyFsckSysAdminAllowed,
            shellSuTransitionAllowed = snapshot.javaDirtyPolicyShellSuTransitionAllowed,
            adbdAdbrootBinderCallAllowed = snapshot.javaDirtyPolicyAdbdAdbrootBinderCallAllowed,
            magiskBinderCallAllowed = snapshot.javaDirtyPolicyMagiskBinderCallAllowed,
            ksuFileReadAllowed = snapshot.javaDirtyPolicyKsuFileReadAllowed,
            lsposedFileReadAllowed = snapshot.javaDirtyPolicyLsposedFileReadAllowed,
            magiskDroidspacesdTransitionAllowed = snapshot.javaDirtyPolicyMagiskDroidspacesdTransitionAllowed,
            suDroidspacesdTransitionAllowed = snapshot.javaDirtyPolicySuDroidspacesdTransitionAllowed,
            systemServerDroidspacesdBinderCallAllowed = snapshot.javaDirtyPolicySystemServerDroidspacesdBinderCallAllowed,
            msdAppDaemonConnectAllowed = snapshot.javaDirtyPolicyMsdAppDaemonConnectAllowed,
            msdDaemonSelfConnectAllowed = snapshot.javaDirtyPolicyMsdDaemonSelfConnectAllowed,
            msdDaemonSelinuxfsReadAllowed = snapshot.javaDirtyPolicyMsdDaemonSelinuxfsReadAllowed,
            msdDaemonConfigfsDirSearchAllowed = snapshot.javaDirtyPolicyMsdDaemonConfigfsDirSearchAllowed,
            msdDaemonConfigfsFileWriteAllowed = snapshot.javaDirtyPolicyMsdDaemonConfigfsFileWriteAllowed,
            xposedDataFileReadAllowed = snapshot.javaDirtyPolicyXposedDataFileReadAllowed,
            zygoteAdbDataSearchAllowed = snapshot.javaDirtyPolicyZygoteAdbDataSearchAllowed,
            failureReason = snapshot.javaDirtyPolicyFailureReason,
            additionalRules = snapshot.javaDirtyPolicyAdditionalRules,
        )
    }
}

private val ADDITIONAL_DIRTY_POLICY_EDGES = listOf(
    "rootfs -> tmpfs associate",
    "kernel -> tmpfs fifo open",
    "kernel -> adb_data_file read",
    SYSTEM_SERVER_APK_EXECUTE_EDGE,
    DEX2OAT_EXECUTE_NO_TRANS_EDGE,
)

private const val DEX2OAT_EXECUTE_NO_TRANS_EDGE = "dex2oat -> dex2oat_exec execute_no_trans"
private const val SYSTEM_SERVER_APK_EXECUTE_EDGE = "system_server -> apk_data_file execute"
