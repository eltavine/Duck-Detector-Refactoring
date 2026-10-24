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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

internal fun SelinuxContextValiditySnapshot.applyJavaDirtyPolicyResults(
    isUserBuild: Boolean,
    checkAccess: (String, String, String, String) -> Boolean?,
): SelinuxContextValiditySnapshot {
    val dirtyPolicyBase = copy(
        javaDirtyPolicyCarrierContext = carrierContext,
        javaDirtyPolicyCarrierMatchesExpected = carrierMatchesExpected,
        javaDirtyPolicyQueryMethod = DIRTY_POLICY_QUERY_METHOD,
    )

    val failureReason = SelinuxContextValidityCarrierService.procAttrCurrentGateFailureReason(
        snapshot = dirtyPolicyBase,
        appUid = 0,
        uid = 0,
    )?.takeUnless { it.startsWith("UID mismatch:") }
        ?.takeUnless { it == "Application UID unavailable for app_zygote attr/current probe." }
    if (failureReason != null) {
        return dirtyPolicyBase.copy(
            javaDirtyPolicyAvailable = false,
            javaDirtyPolicyProbeAttempted = false,
            javaDirtyPolicyFailureReason = failureReason,
        )
    }

    val accessControl = queryAccessPair(
        checkAccess,
        APP_ZYGOTE_PREFIX,
        ISOLATED_APP_CONTEXT,
        "process",
        "dyntransition",
    )
    val negativeControl = queryAccessPair(
        checkAccess,
        UNTRUSTED_APP_CONTEXT,
        DIRTY_POLICY_NEGATIVE_CONTROL_CONTEXT,
        "binder",
        "call",
    )
    if (accessControl.first == null && accessControl.second == null &&
        negativeControl.first == null && negativeControl.second == null
    ) {
        return dirtyPolicyBase.copy(
            javaDirtyPolicyAvailable = false,
            javaDirtyPolicyProbeAttempted = false,
            javaDirtyPolicyFailureReason = "SELinux.checkSELinuxAccess unavailable from preload carrier.",
        )
    }

    val accessControlAllowed = accessControl.stable.thenValue(accessControl.first)
    val negativeControlRejected =
        negativeControl.stable.thenValue(negativeControl.first?.not())
    val controlsPassed =
        accessControl.stable && accessControl.first == true &&
            negativeControl.stable && negativeControl.first == false
    var stable = accessControl.stable && negativeControl.stable

    val systemServerExecmem = queryAccessPair(
        checkAccess,
        SYSTEM_SERVER_CONTEXT,
        SYSTEM_SERVER_CONTEXT,
        "process",
        "execmem",
    )
    val fsckSysAdmin = queryAccessPair(
        checkAccess,
        FSCK_UNTRUSTED_CONTEXT,
        FSCK_UNTRUSTED_CONTEXT,
        "capability",
        "sys_admin",
    )
    val shellSuTransition = queryAccessPair(
        checkAccess,
        SHELL_CONTEXT,
        SU_CONTEXT,
        "process",
        "transition",
    )
    val adbdAdbrootBinder = queryAccessPair(
        checkAccess,
        ADBD_CONTEXT,
        ADBROOT_CONTEXT,
        "binder",
        "call",
    )
    val magiskBinder = queryAccessPair(
        checkAccess,
        UNTRUSTED_APP_CONTEXT,
        MAGISK_CONTEXT,
        "binder",
        "call",
    )
    val ksuFileRead = queryAccessPair(
        checkAccess,
        UNTRUSTED_APP_CONTEXT,
        KSU_FILE_CONTEXT,
        "file",
        "read",
    )
    val lsposedFileRead = queryAccessPair(
        checkAccess,
        UNTRUSTED_APP_CONTEXT,
        LSPOSED_FILE_CONTEXT,
        "file",
        "read",
    )
    val magiskDroidspacesdTransition = queryAccessPair(
        checkAccess,
        MAGISK_CONTEXT,
        DROIDSPACESD_CONTEXT,
        "process",
        "dyntransition",
    )
    val suDroidspacesdTransition = queryAccessPair(
        checkAccess,
        SU_CONTEXT,
        DROIDSPACESD_CONTEXT,
        "process",
        "dyntransition",
    )
    val systemServerDroidspacesdBinder = queryAccessPair(
        checkAccess,
        SYSTEM_SERVER_CONTEXT,
        DROIDSPACESD_CONTEXT,
        "binder",
        "call",
    )
    val msdAppDaemonConnect = queryAccessPair(
        checkAccess,
        MSD_APP_CONTEXT,
        MSD_DAEMON_CONTEXT,
        "unix_stream_socket",
        "connectto",
    )
    val msdDaemonSelfConnect = queryAccessPair(
        checkAccess,
        MSD_DAEMON_CONTEXT,
        MSD_DAEMON_CONTEXT,
        "unix_stream_socket",
        "connectto",
    )
    val msdDaemonSelinuxfsRead = queryAccessPair(
        checkAccess,
        MSD_DAEMON_CONTEXT,
        SELINUXFS_CONTEXT,
        "file",
        "read",
    )
    val msdDaemonConfigfsDirSearch = queryAccessPair(
        checkAccess,
        MSD_DAEMON_CONTEXT,
        CONFIGFS_CONTEXT,
        "dir",
        "search",
    )
    val msdDaemonConfigfsFileWrite = queryAccessPair(
        checkAccess,
        MSD_DAEMON_CONTEXT,
        CONFIGFS_CONTEXT,
        "file",
        "write",
    )
    val xposedDataRead = queryAccessPair(
        checkAccess,
        UNTRUSTED_APP_CONTEXT,
        XPOSED_DATA_CONTEXT,
        "file",
        "read",
    )
    val zygoteAdbDataSearch = queryAccessPair(
        checkAccess,
        ZYGOTE_CONTEXT,
        ADB_DATA_FILE_CONTEXT,
        "dir",
        "search",
    )
    val extraPairs = EXTRA_DIRTY_POLICY_RULES.associate { rule ->
        rule.name to queryAccessPair(checkAccess, rule.source, rule.target, rule.clazz, rule.permission)
    }
    stable = stable &&
        systemServerExecmem.stable &&
        fsckSysAdmin.stable &&
        adbdAdbrootBinder.stable &&
        magiskBinder.stable &&
        ksuFileRead.stable &&
        lsposedFileRead.stable &&
        magiskDroidspacesdTransition.stable &&
        suDroidspacesdTransition.stable &&
        systemServerDroidspacesdBinder.stable &&
        msdAppDaemonConnect.stable &&
        msdDaemonSelfConnect.stable &&
        msdDaemonSelinuxfsRead.stable &&
        msdDaemonConfigfsDirSearch.stable &&
        msdDaemonConfigfsFileWrite.stable &&
        xposedDataRead.stable &&
        zygoteAdbDataSearch.stable &&
        (!isUserBuild || shellSuTransition.stable)

    val notes = buildList {
        add("Carrier context: ${carrierContext ?: "<unreadable>"}")
        add("Query method: $DIRTY_POLICY_QUERY_METHOD")
        add(accessControl.note("Access control"))
        add(negativeControl.note("Negative control"))
        add(systemServerExecmem.note("system_server execmem"))
        add(fsckSysAdmin.note("fsck_untrusted sys_admin"))
        if (isUserBuild) {
            add(shellSuTransition.note("shell -> su transition"))
        } else {
            add("shell -> su transition skipped because ro.build.type is not user.")
        }
        add(adbdAdbrootBinder.note("adbd -> adbroot binder"))
        add(magiskBinder.note("untrusted_app -> magisk binder"))
        add(ksuFileRead.note("untrusted_app -> ksu_file read"))
        add(lsposedFileRead.note("untrusted_app -> lsposed_file read"))
        add(magiskDroidspacesdTransition.note("magisk -> droidspacesd dyntransition"))
        add(suDroidspacesdTransition.note("su -> droidspacesd dyntransition"))
        add(systemServerDroidspacesdBinder.note("system_server -> droidspacesd binder"))
        add(msdAppDaemonConnect.note("msd_app -> msd_daemon connectto"))
        add(msdDaemonSelfConnect.note("msd_daemon -> msd_daemon connectto"))
        add(msdDaemonSelinuxfsRead.note("msd_daemon -> selinuxfs read"))
        add(msdDaemonConfigfsDirSearch.note("msd_daemon -> configfs dir search"))
        add(msdDaemonConfigfsFileWrite.note("msd_daemon -> configfs file write"))
        add(xposedDataRead.note("untrusted_app -> xposed_data read"))
        add(zygoteAdbDataSearch.note("zygote -> adb_data_file search"))
        extraPairs.forEach { (name, pair) -> add(pair.note(name)) }
    }

    val dirtyPolicyFailureReason = when {
        !stable -> "Dirty policy oracle repeated inconsistently."
        !controlsPassed -> "Dirty policy oracle self-test failed."
        else -> null
    }

    return copy(
        javaDirtyPolicyAvailable = true,
        javaDirtyPolicyProbeAttempted = true,
        javaDirtyPolicyCarrierContext = carrierContext,
        javaDirtyPolicyCarrierMatchesExpected = carrierMatchesExpected,
        javaDirtyPolicyControlsPassed = controlsPassed,
        javaDirtyPolicyStable = stable,
        javaDirtyPolicyQueryMethod = DIRTY_POLICY_QUERY_METHOD,
        javaDirtyPolicyAccessControlAllowed = accessControlAllowed,
        javaDirtyPolicyNegativeControlRejected = negativeControlRejected,
        javaDirtyPolicySystemServerExecmemAllowed = systemServerExecmem.stable.thenValue(systemServerExecmem.first),
        javaDirtyPolicyFsckSysAdminAllowed = fsckSysAdmin.stable.thenValue(fsckSysAdmin.first),
        javaDirtyPolicyShellSuTransitionAllowed = if (isUserBuild) {
            shellSuTransition.stable.thenValue(shellSuTransition.first)
        } else {
            null
        },
        javaDirtyPolicyAdbdAdbrootBinderCallAllowed = adbdAdbrootBinder.stable.thenValue(adbdAdbrootBinder.first),
        javaDirtyPolicyMagiskBinderCallAllowed = magiskBinder.stable.thenValue(magiskBinder.first),
        javaDirtyPolicyKsuFileReadAllowed = ksuFileRead.stable.thenValue(ksuFileRead.first),
        javaDirtyPolicyLsposedFileReadAllowed = lsposedFileRead.stable.thenValue(lsposedFileRead.first),
        javaDirtyPolicyMagiskDroidspacesdTransitionAllowed = magiskDroidspacesdTransition.stable.thenValue(magiskDroidspacesdTransition.first),
        javaDirtyPolicySuDroidspacesdTransitionAllowed = suDroidspacesdTransition.stable.thenValue(suDroidspacesdTransition.first),
        javaDirtyPolicySystemServerDroidspacesdBinderCallAllowed = systemServerDroidspacesdBinder.stable.thenValue(systemServerDroidspacesdBinder.first),
        javaDirtyPolicyMsdAppDaemonConnectAllowed = msdAppDaemonConnect.stable.thenValue(msdAppDaemonConnect.first),
        javaDirtyPolicyMsdDaemonSelfConnectAllowed = msdDaemonSelfConnect.stable.thenValue(msdDaemonSelfConnect.first),
        javaDirtyPolicyMsdDaemonSelinuxfsReadAllowed = msdDaemonSelinuxfsRead.stable.thenValue(msdDaemonSelinuxfsRead.first),
        javaDirtyPolicyMsdDaemonConfigfsDirSearchAllowed = msdDaemonConfigfsDirSearch.stable.thenValue(msdDaemonConfigfsDirSearch.first),
        javaDirtyPolicyMsdDaemonConfigfsFileWriteAllowed = msdDaemonConfigfsFileWrite.stable.thenValue(msdDaemonConfigfsFileWrite.first),
        javaDirtyPolicyXposedDataFileReadAllowed = xposedDataRead.stable.thenValue(xposedDataRead.first),
        javaDirtyPolicyZygoteAdbDataSearchAllowed = zygoteAdbDataSearch.stable.thenValue(zygoteAdbDataSearch.first),
        javaDirtyPolicyAdditionalRules = extraPairs.mapNotNull { (name, pair) ->
            pair.stable.thenValue(pair.first)?.let { name to it }
        }.toMap(),
        javaDirtyPolicyFailureReason = dirtyPolicyFailureReason,
        javaDirtyPolicyNotes = notes,
    )
}

private data class AccessPair(
    val first: Boolean?,
    val second: Boolean?,
) {
    val stable: Boolean
        get() = first == second

    fun note(label: String): String {
        val verdict = when (first) {
            true -> "allowed"
            false -> "denied"
            null -> "unavailable"
        }
        return buildString {
            append(label)
            append('=')
            append(verdict)
            if (!stable) {
                append(" (unstable)")
            }
        }
    }
}

private fun queryAccessPair(
    checkAccess: (String, String, String, String) -> Boolean?,
    source: String,
    target: String,
    targetClass: String,
    permission: String,
): AccessPair {
    return AccessPair(
        first = checkAccess(source, target, targetClass, permission),
        second = checkAccess(source, target, targetClass, permission),
    )
}

private fun <T> Boolean.thenValue(value: T?): T? {
    return if (this) value else null
}

internal const val APP_ZYGOTE_PREFIX = "u:r:app_zygote:s0"
internal const val ISOLATED_APP_CONTEXT = "u:r:isolated_app:s0"
private const val UNTRUSTED_APP_CONTEXT = "u:r:untrusted_app:s0"
private const val SYSTEM_SERVER_CONTEXT = "u:r:system_server:s0"
private const val FSCK_UNTRUSTED_CONTEXT = "u:r:fsck_untrusted:s0"
private const val SHELL_CONTEXT = "u:r:shell:s0"
private const val SU_CONTEXT = "u:r:su:s0"
private const val ADBD_CONTEXT = "u:r:adbd:s0"
private const val ADBROOT_CONTEXT = "u:r:adbroot:s0"
private const val MAGISK_CONTEXT = "u:r:magisk:s0"
private const val DROIDSPACESD_CONTEXT = "u:r:droidspacesd:s0"
private const val KSU_FILE_CONTEXT = "u:object_r:ksu_file:s0"
private const val LSPOSED_FILE_CONTEXT = "u:object_r:lsposed_file:s0"
private const val XPOSED_DATA_CONTEXT = "u:object_r:xposed_data:s0"
private const val ZYGOTE_CONTEXT = "u:r:zygote:s0"
private const val ADB_DATA_FILE_CONTEXT = "u:object_r:adb_data_file:s0"
private const val MSD_APP_CONTEXT = "u:r:msd_app:s0"
private const val MSD_DAEMON_CONTEXT = "u:r:msd_daemon:s0"
private const val SELINUXFS_CONTEXT = "u:object_r:selinuxfs:s0"
private const val CONFIGFS_CONTEXT = "u:object_r:configfs:s0"
private const val DIRTY_POLICY_NEGATIVE_CONTROL_CONTEXT =
    "u:r:duckdetector_dirty_policy_sentinel:s0"
internal const val DIRTY_POLICY_QUERY_METHOD = "android.os.SELinux.checkSELinuxAccess"

private data class ExtraDirtyPolicyRule(
    val name: String,
    val source: String,
    val target: String,
    val clazz: String,
    val permission: String,
)

private val EXTRA_DIRTY_POLICY_RULES = listOf(
    ExtraDirtyPolicyRule("rootfs -> tmpfs associate", "u:object_r:rootfs:s0", "u:object_r:tmpfs:s0", "filesystem", "associate"),
    ExtraDirtyPolicyRule("kernel -> tmpfs fifo open", "u:r:kernel:s0", "u:object_r:tmpfs:s0", "fifo_file", "open"),
    ExtraDirtyPolicyRule("kernel -> adb_data_file read", "u:r:kernel:s0", "u:object_r:adb_data_file:s0", "file", "read"),
    ExtraDirtyPolicyRule("system_server -> apk_data_file execute", "u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute"),
    ExtraDirtyPolicyRule("dex2oat -> dex2oat_exec execute_no_trans", "u:r:dex2oat:s0", "u:object_r:dex2oat_exec:s0", "file", "execute_no_trans"),
)
