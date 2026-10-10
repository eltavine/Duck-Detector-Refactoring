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

import android.content.pm.ApplicationInfo
import android.os.Build
import android.system.Os
import java.lang.reflect.Method

public class SelinuxContextValidityPreload {

    private val sidtabProbe = SelinuxSidtabProbe()
    private val bridge = SelinuxContextValidityBridge()
    private val statusPageProbe = SelinuxStatusPageProbe()
    private val procAttrCurrentProbe = SelinuxProcAttrCurrentProbe()
    private val avcLookupProbe = SelinuxAvcLookupProbe()
    private val policyloadSeqnoProbe = SelinuxPolicyloadSeqnoProbe()

    /**
     * Captures the carrier evidence in the app zygote. [trace] is called before each step, so an
     * app zygote that is killed partway through still leaves a record of the step it had reached.
     */
    public fun preload(
        appInfo: ApplicationInfo,
        trace: (step: String) -> Unit = {},
        beforeCollection: () -> Unit,
    ) {
        // Kept outside the try: a finished experiment's kernel side effects outlive a later failure.
        var sidtab = SelinuxSidtabSnapshot()
        var procAttrResults: List<SelinuxProcAttrCurrentResult>? = null
        var avcLookup = SelinuxAvcLookupSnapshot()
        val payload = try {
            beforeCollection()
            val currentUid = Os.getuid()
            // Before anything that lets libselinux map the status page: on a kernel that breaks that
            // node, the first access check kills this carrier.
            trace("selinux: status page probe")
            val statusPage = statusPageProbe.inspect()
            val accessCheckBlockReason = statusPage.accessCheckBlockReason
            // Direct I/O, isolated from libselinux and from any identity change in its child.
            trace("selinux: SID-table experiment")
            sidtab = if (currentUid == appInfo.uid) sidtabProbe.inspect() else SelinuxSidtabSnapshot(
                collection = SelinuxSidtabCollection.UNSUPPORTED,
                failureReason = "Carrier UID does not match the application UID.",
            )
            val baseSnapshot = collectBaseSnapshot(currentUid, appInfo.uid, accessCheckBlockReason, trace)
                .copy(sidtab = sidtab)
            var dirtyPolicyTraced = false
            val snapshot = augmentPreloadSnapshot(
                baseSnapshot = baseSnapshot,
                currentUid = currentUid,
                appUid = appInfo.uid,
                isUserBuild = Build.TYPE == "user",
                accessCheckBlockReason = accessCheckBlockReason,
                inspectProcAttrCurrent = {
                    trace("selinux: controlled proc attr current child")
                    procAttrCurrentProbe.inspect().also { procAttrResults = it }
                },
                inspectAvcLookup = {
                    trace("selinux: app zygote AVC lookup child")
                    avcLookupProbe.inspect().also {
                        avcLookup = it
                        trace("selinux: AVC lookup state=${it.state} step=${it.step} errno=${it.errno} rounds=${it.rounds}")
                    }
                },
                inspectPolicyloadSeqno = {
                    trace("selinux: policyload seqno")
                    policyloadSeqnoProbe.inspect(statusPage)
                },
                checkAccess = { source, target, targetClass, permission ->
                    if (!dirtyPolicyTraced) {
                        dirtyPolicyTraced = true
                        trace("selinux: java dirty policy checks")
                    }
                    checkSelinuxAccess(source, target, targetClass, permission)
                },
            )
            SelinuxContextValidityPayloadCodec.encode(snapshot)
        } catch (throwable: Throwable) {
            fallbackPayload(throwable.message ?: "SELinux app zygote preload failed.", sidtab, procAttrResults, avcLookup)
        } finally {
            // The access checks above leave libselinux's AVC netlink socket open. Before Android 12,
            // AppZygoteInit does not exempt what doPreload opened, so the next fork of this app zygote
            // would abort on it: frameworks/base core/jni/fd_utils.cpp accepts only named AF_UNIX
            // sockets ("Unable to get socket name").
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
                SelinuxContextValidityBridge.closeProcessLocalAvc()
            }
        }
        SelinuxContextValidityBridge.setPreloadedRawData(payload)
    }

    private fun collectBaseSnapshot(
        currentUid: Int,
        appUid: Int,
        accessCheckBlockReason: String?,
        trace: (step: String) -> Unit,
    ): SelinuxContextValiditySnapshot {
        if (currentUid != appUid) {
            return fallbackSnapshot("UID mismatch: $currentUid != app uid $appUid.")
        }
        val allowAccessChecks = accessCheckBlockReason == null
        trace("selinux: native context oracle")
        val nativeSnapshot = collectNativeCarrierSnapshot(allowAccessChecks)
        trace("selinux: java carrier checks")
        val javaCarrierSnapshot = collectJavaCarrierSnapshot(currentUid, appUid, allowAccessChecks)
        val merged = mergeCarrierSelfCheckSnapshot(
            nativeSnapshot = nativeSnapshot,
            javaCarrierSnapshot = javaCarrierSnapshot,
        )
        accessCheckBlockReason ?: return merged
        return merged.copy(notes = merged.notes + "Dyntransition self-check: $accessCheckBlockReason")
    }

    private fun collectNativeCarrierSnapshot(allowAccessChecks: Boolean): SelinuxContextValiditySnapshot {
        if (!SelinuxContextValidityBridge.isNativeLibraryLoaded) {
            return SelinuxContextValiditySnapshot(
                failureReason = "duckdetector native library unavailable from preload carrier.",
            )
        }
        return runCatching {
            bridge.parse(SelinuxContextValidityBridge.nativeCollectContextValiditySnapshot(allowAccessChecks))
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
        allowAccessChecks: Boolean,
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
        val dyntransitionCheckPassed = if (allowAccessChecks) {
            checkSelinuxAccess(
                APP_ZYGOTE_PREFIX,
                ISOLATED_APP_CONTEXT,
                "process",
                "dyntransition",
            )
        } else {
            null
        }
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

    internal fun fallbackPayload(
        reason: String,
        sidtab: SelinuxSidtabSnapshot = SelinuxSidtabSnapshot(),
        procAttrResults: List<SelinuxProcAttrCurrentResult>? = null,
        avcLookup: SelinuxAvcLookupSnapshot = SelinuxAvcLookupSnapshot(),
    ): String {
        return SelinuxContextValidityPayloadCodec.encode(fallbackSnapshot(reason).copy(
            sidtab = sidtab,
            procAttrCurrentProbeAttempted = procAttrResults != null,
            procAttrCurrentResults = procAttrResults.orEmpty(),
            avcLookup = avcLookup,
        ))
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

    public companion object {
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
            accessCheckBlockReason: String?,
            inspectProcAttrCurrent: () -> List<com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxProcAttrCurrentResult>,
            inspectAvcLookup: () -> SelinuxAvcLookupSnapshot = { SelinuxAvcLookupSnapshot() },
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

            val snapshotWithAvc = snapshotWithProcAttr.copy(
                avcLookup = carrierGateFailureReason?.let {
                    SelinuxAvcLookupSnapshot(state = SelinuxAvcLookupState.UNSUPPORTED, failureReason = it)
                } ?: inspectAvcLookup(),
            )
            val snapshotWithPolicyloadSeqno = snapshotWithAvc.applyPolicyloadSeqnoResult(
                failureReason = carrierGateFailureReason,
                inspectPolicyloadSeqno = inspectPolicyloadSeqno,
            )

            // The first android.os.SELinux.checkSELinuxAccess makes libselinux map and read the status page.
            accessCheckBlockReason?.let { reason ->
                return snapshotWithPolicyloadSeqno.copy(
                    javaDirtyPolicyAvailable = false,
                    javaDirtyPolicyProbeAttempted = false,
                    javaDirtyPolicyCarrierContext = snapshotWithPolicyloadSeqno.carrierContext,
                    javaDirtyPolicyCarrierMatchesExpected = snapshotWithPolicyloadSeqno.carrierMatchesExpected,
                    javaDirtyPolicyQueryMethod = DIRTY_POLICY_QUERY_METHOD,
                    javaDirtyPolicyFailureReason = reason,
                )
            }
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
    }
}
