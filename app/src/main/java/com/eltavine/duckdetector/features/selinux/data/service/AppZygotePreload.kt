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

package com.eltavine.duckdetector.features.selinux.data.service

import android.app.ZygotePreload
import android.content.pm.ApplicationInfo
import android.os.Build
import android.system.Os
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValidityBridge
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValidityPayloadCodec
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValiditySnapshot
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxPolicyloadSeqnoProbe
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxPolicyloadSeqnoResult
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxPolicyloadSeqnoState
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxProcAttrCurrentProbe
import java.lang.reflect.Method

class AppZygotePreload : ZygotePreload {

    private val bridge = SelinuxContextValidityBridge()
    private val procAttrCurrentProbe = SelinuxProcAttrCurrentProbe()
    private val policyloadSeqnoProbe = SelinuxPolicyloadSeqnoProbe()

    override fun doPreload(appInfo: ApplicationInfo) {
        val payload = runCatching {
            val currentUid = Os.getuid()
            val baseSnapshot = collectBaseSnapshot(currentUid, appInfo.uid)
            val snapshot = augmentPreloadSnapshot(
                baseSnapshot = baseSnapshot,
                currentUid = currentUid,
                appUid = appInfo.uid,
                isUserBuild = Build.TYPE == "user",
                inspectProcAttrCurrent = procAttrCurrentProbe::inspect,
                inspectPolicyloadSeqno = policyloadSeqnoProbe::inspect,
                checkAccess = ::checkSelinuxAccess,
            )
            SelinuxContextValidityPayloadCodec.encode(snapshot)
        }.getOrElse { throwable ->
            fallbackPayload(throwable.message ?: "SELinux app zygote preload failed.")
        }
        SelinuxContextValidityBridge.setPreloadedRawData(payload)
    }

    private fun collectBaseSnapshot(
        currentUid: Int,
        appUid: Int,
    ): SelinuxContextValiditySnapshot {
        if (currentUid != appUid) {
            return fallbackSnapshot("UID mismatch: $currentUid != app uid $appUid.")
        }
        val nativeSnapshot = collectNativeCarrierSnapshot()
        val javaCarrierSnapshot = collectJavaCarrierSnapshot(currentUid, appUid)
        return mergeCarrierSelfCheckSnapshot(
            nativeSnapshot = nativeSnapshot,
            javaCarrierSnapshot = javaCarrierSnapshot,
        )
    }

    private fun collectNativeCarrierSnapshot(): SelinuxContextValiditySnapshot {
        if (!SelinuxContextValidityBridge.isNativeLibraryLoaded) {
            return SelinuxContextValiditySnapshot(
                failureReason = "duckdetector native library unavailable from preload carrier.",
            )
        }
        return runCatching {
            bridge.parse(SelinuxContextValidityBridge.nativeCollectContextValiditySnapshot())
        }.getOrElse { throwable ->
            SelinuxContextValiditySnapshot(
                failureReason = throwable.message ?: "Dedicated native app_zygote oracle failed.",
            )
        }
    }

    private fun checkSelinuxAccess(
        source: String,
        target: String,
        targetClass: String,
        permission: String,
    ): Boolean? {
        return runCatching {
            val selinuxClass = Class.forName("android.os.SELinux")
            val method = resolveCheckSelinuxAccessMethod(selinuxClass)
            method.invoke(null, source, target, targetClass, permission) as? Boolean
        }.getOrNull()
    }

    private fun collectJavaCarrierSnapshot(
        currentUid: Int,
        appUid: Int,
    ): SelinuxContextValiditySnapshot {
        if (currentUid != appUid) {
            return fallbackSnapshot("UID mismatch: $currentUid != app uid $appUid.")
        }
        val selinuxClass = runCatching { Class.forName("android.os.SELinux") }.getOrNull()
            ?: return SelinuxContextValiditySnapshot(
                failureReason = "android.os.SELinux unavailable from preload carrier.",
            )
        val carrierContext = invokeSelinuxStringNoArgs(selinuxClass, "getContext")
        val pidContext = invokeSelinuxStringIntArg(selinuxClass, "getPidContext", Os.getpid())
        val procSelfContext = invokeSelinuxStringStringArg(selinuxClass, "getFileContext", "/proc/self")
        val selinuxEnabled = invokeSelinuxBoolean(selinuxClass, "isSELinuxEnabled")
        val selinuxEnforced = invokeSelinuxBoolean(selinuxClass, "isSELinuxEnforced")
        val dyntransitionCheckPassed = checkSelinuxAccess(
            APP_ZYGOTE_PREFIX,
            ISOLATED_APP_CONTEXT,
            "process",
            "dyntransition",
        )
        return SelinuxContextValiditySnapshot(
            available = !carrierContext.isNullOrBlank(),
            carrierContext = carrierContext,
            carrierMatchesExpected = carrierContext?.startsWith(APP_ZYGOTE_PREFIX) == true,
            selinuxEnabled = selinuxEnabled,
            selinuxEnforced = selinuxEnforced,
            pidContextMatchesCurrent = if (carrierContext != null && pidContext != null) pidContext == carrierContext else null,
            procSelfContextMatchesCurrent = if (carrierContext != null && procSelfContext != null) procSelfContext == carrierContext else null,
            dyntransitionCheckPassed = dyntransitionCheckPassed,
        )
    }

    private fun invokeSelinuxBoolean(
        selinuxClass: Class<*>,
        methodName: String,
    ): Boolean? {
        return runCatching {
            selinuxClass.getMethod(methodName).invoke(null) as? Boolean
        }.getOrNull()
    }

    private fun invokeSelinuxStringNoArgs(
        selinuxClass: Class<*>,
        methodName: String,
    ): String? {
        return runCatching {
            selinuxClass.getMethod(methodName).invoke(null) as? String
        }.getOrNull()
    }

    private fun invokeSelinuxStringIntArg(
        selinuxClass: Class<*>,
        methodName: String,
        value: Int,
    ): String? {
        return runCatching {
            selinuxClass.getMethod(methodName, Int::class.javaPrimitiveType).invoke(null, value) as? String
        }.getOrNull()
    }

    private fun invokeSelinuxStringStringArg(
        selinuxClass: Class<*>,
        methodName: String,
        value: String,
    ): String? {
        return runCatching {
            selinuxClass.getMethod(methodName, String::class.java).invoke(null, value) as? String
        }.getOrNull()
    }

    private fun resolveCheckSelinuxAccessMethod(selinuxClass: Class<*>): Method {
        return selinuxClass.getMethod(
            "checkSELinuxAccess",
            String::class.java,
            String::class.java,
            String::class.java,
            String::class.java,
        )
    }

    private fun fallbackPayload(reason: String): String {
        return SelinuxContextValidityPayloadCodec.encode(fallbackSnapshot(reason))
    }

    private fun fallbackSnapshot(reason: String): SelinuxContextValiditySnapshot {
        return SelinuxContextValiditySnapshot(
            dirtyPolicyQueryMethod = DIRTY_POLICY_QUERY_METHOD,
            dirtyPolicyFailureReason = reason,
            dirtyPolicyNotes = listOf(FALLBACK_NOTE),
            policyloadSeqnoState = SelinuxPolicyloadSeqnoState.UNAVAILABLE.name,
            policyloadSeqnoFailureReason = reason,
            policyloadSeqnoNotes = listOf(FALLBACK_NOTE),
            failureReason = reason,
            notes = listOf(FALLBACK_NOTE),
        )
    }

    companion object {
        private const val APP_ZYGOTE_PREFIX = "u:r:app_zygote:s0"
        private const val ISOLATED_APP_CONTEXT = "u:r:isolated_app:s0"
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
        private const val DIRTY_POLICY_QUERY_METHOD = "android.os.SELinux.checkSELinuxAccess"
        private const val FALLBACK_NOTE = "Kotlin preload fallback produced a parseable SELinux snapshot."
        private const val POLICYLOAD_SEQNO_PRELOAD_NOTE =
            "zygotePreloadName is required: the policyload/access seqno oracle must run before the isolated child loses app_zygote SELinuxfs access."

        internal fun mergeCarrierSelfCheckSnapshot(
            nativeSnapshot: SelinuxContextValiditySnapshot,
            javaCarrierSnapshot: SelinuxContextValiditySnapshot,
        ): SelinuxContextValiditySnapshot {
            return nativeSnapshot.copy(
                available = nativeSnapshot.available || javaCarrierSnapshot.available,
                probeAttempted = nativeSnapshot.probeAttempted || javaCarrierSnapshot.available,
                carrierContext = javaCarrierSnapshot.carrierContext ?: nativeSnapshot.carrierContext,
                carrierMatchesExpected = if (javaCarrierSnapshot.carrierContext != null) {
                    javaCarrierSnapshot.carrierMatchesExpected
                } else {
                    nativeSnapshot.carrierMatchesExpected
                },
                selinuxEnabled = javaCarrierSnapshot.selinuxEnabled ?: nativeSnapshot.selinuxEnabled,
                selinuxEnforced = javaCarrierSnapshot.selinuxEnforced ?: nativeSnapshot.selinuxEnforced,
                pidContextMatchesCurrent = javaCarrierSnapshot.pidContextMatchesCurrent
                    ?: nativeSnapshot.pidContextMatchesCurrent,
                procSelfContextMatchesCurrent = javaCarrierSnapshot.procSelfContextMatchesCurrent
                    ?: nativeSnapshot.procSelfContextMatchesCurrent,
                dyntransitionCheckPassed = javaCarrierSnapshot.dyntransitionCheckPassed
                    ?: nativeSnapshot.dyntransitionCheckPassed,
                failureReason = nativeSnapshot.failureReason ?: javaCarrierSnapshot.failureReason,
            )
        }

        internal fun augmentPreloadSnapshot(
            baseSnapshot: SelinuxContextValiditySnapshot,
            currentUid: Int,
            appUid: Int,
            isUserBuild: Boolean,
            inspectProcAttrCurrent: () -> List<com.eltavine.duckdetector.features.selinux.data.probes.SelinuxProcAttrCurrentResult>,
            inspectPolicyloadSeqno: () -> SelinuxPolicyloadSeqnoResult,
            checkAccess: (String, String, String, String) -> Boolean?,
        ): SelinuxContextValiditySnapshot {
            val carrierGateFailureReason = SelinuxContextValidityCarrierService.procAttrCurrentGateFailureReason(
                snapshot = baseSnapshot,
                appUid = appUid,
                uid = currentUid,
            )
            val snapshotWithProcAttr = if (carrierGateFailureReason == null) {
                baseSnapshot.copy(
                    procAttrCurrentProbeAttempted = true,
                    procAttrCurrentResults = inspectProcAttrCurrent(),
                    procAttrCurrentFailureReason = null,
                )
            } else {
                baseSnapshot.copy(
                    procAttrCurrentProbeAttempted = false,
                    procAttrCurrentResults = emptyList(),
                    procAttrCurrentFailureReason = carrierGateFailureReason,
                )
            }

            val snapshotWithPolicyloadSeqno = snapshotWithProcAttr.applyPolicyloadSeqnoResult(
                failureReason = carrierGateFailureReason,
                inspectPolicyloadSeqno = inspectPolicyloadSeqno,
            )

            return snapshotWithPolicyloadSeqno.applyJavaDirtyPolicyResults(
                isUserBuild = isUserBuild,
                checkAccess = checkAccess,
            )
        }

        private fun SelinuxContextValiditySnapshot.applyPolicyloadSeqnoResult(
            failureReason: String?,
            inspectPolicyloadSeqno: () -> SelinuxPolicyloadSeqnoResult,
        ): SelinuxContextValiditySnapshot {
            if (failureReason != null) {
                return copy(
                    policyloadSeqnoAvailable = false,
                    policyloadSeqnoProbeAttempted = false,
                    policyloadSeqnoState = SelinuxPolicyloadSeqnoState.UNAVAILABLE.name,
                    policyloadSeqnoCarrierContext = carrierContext,
                    policyloadSeqnoFailureReason = failureReason,
                    policyloadSeqnoNotes = listOf(POLICYLOAD_SEQNO_PRELOAD_NOTE),
                )
            }
            val result = inspectPolicyloadSeqno()
            return copy(
                policyloadSeqnoAvailable = result.available,
                policyloadSeqnoProbeAttempted = result.probeAttempted,
                policyloadSeqnoState = result.state.name,
                policyloadSeqnoCarrierContext = carrierContext,
                policyloadSeqnoStatusSequence = result.statusSequence,
                policyloadSeqnoStatusPolicyload = result.statusPolicyload,
                policyloadSeqnoAccessSeqno = result.accessSeqno,
                policyloadSeqnoProcessClass = result.processClass,
                policyloadSeqnoFailureReason = result.failureReason,
                policyloadSeqnoNotes = result.notes.ifEmpty { listOf(POLICYLOAD_SEQNO_PRELOAD_NOTE) },
            )
        }

        private fun SelinuxContextValiditySnapshot.applyJavaDirtyPolicyResults(
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
    }
}
