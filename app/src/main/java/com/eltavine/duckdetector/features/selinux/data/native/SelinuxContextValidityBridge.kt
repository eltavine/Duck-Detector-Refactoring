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

package com.eltavine.duckdetector.features.selinux.data.native

import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxProcAttrCurrentPayloadCodec
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxProcAttrCurrentResult

open class SelinuxContextValidityBridge {

    open fun collectLocalSnapshot(): SelinuxContextValiditySnapshot {
        if (!nativeLoaded) {
            return SelinuxContextValiditySnapshot(
                failureReason = "duckdetector native library unavailable.",
            )
        }
        return runCatching {
            parse(nativeCollectContextValiditySnapshotInternal())
        }.getOrDefault(SelinuxContextValiditySnapshot())
    }

    internal fun parse(raw: String): SelinuxContextValiditySnapshot {
        if (raw.isBlank()) {
            return SelinuxContextValiditySnapshot()
        }

        var snapshot = SelinuxContextValiditySnapshot()
        val notes = mutableListOf<String>()
        val dirtyPolicyNotes = mutableListOf<String>()
        val javaDirtyPolicyNotes = mutableListOf<String>()
        val policyloadSeqnoNotes = mutableListOf<String>()
        val procAttrCurrentResults = mutableListOf<SelinuxProcAttrCurrentResult>()

        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when {
                    line.startsWith("DIRTY_POLICY_NOTE=") -> dirtyPolicyNotes += line.removePrefix("DIRTY_POLICY_NOTE=")
                        .decodeValue()

                    line.startsWith("JAVA_DIRTY_POLICY_NOTE=") -> javaDirtyPolicyNotes += line.removePrefix("JAVA_DIRTY_POLICY_NOTE=")
                        .decodeValue()

                    line.startsWith("POLICYLOAD_SEQNO_NOTE=") -> policyloadSeqnoNotes += line.removePrefix("POLICYLOAD_SEQNO_NOTE=")
                        .decodeValue()

                    line.startsWith("NOTE=") -> notes += line.removePrefix("NOTE=")
                        .decodeValue()

                    line.startsWith("PROC_ATTR_CURRENT_RESULT=") ->
                        SelinuxProcAttrCurrentPayloadCodec.decode(
                            line.removePrefix("PROC_ATTR_CURRENT_RESULT=").decodeValue(),
                        )?.let(procAttrCurrentResults::add)

                    line.contains('=') -> {
                        val key = line.substringBefore('=')
                        val value = line.substringAfter('=')
                        snapshot = snapshot.applyEntry(key, value)
                    }
                }
            }

        return snapshot.copy(
            dirtyPolicyNotes = dirtyPolicyNotes,
            javaDirtyPolicyNotes = javaDirtyPolicyNotes,
            policyloadSeqnoNotes = policyloadSeqnoNotes,
            procAttrCurrentResults = procAttrCurrentResults,
            notes = notes,
        )
    }

    private fun SelinuxContextValiditySnapshot.applyEntry(
        key: String,
        value: String,
    ): SelinuxContextValiditySnapshot {
        return when (key) {
            "AVAILABLE" -> copy(available = value.asBool())
            "PROBE_ATTEMPTED" -> copy(probeAttempted = value.asBool())
            "CARRIER_CONTEXT" -> copy(carrierContext = value.decodeValue())
            "CARRIER_MATCHES_EXPECTED" -> copy(carrierMatchesExpected = value.asBool())
            "SELINUX_ENABLED" -> copy(selinuxEnabled = value.asNullableBool())
            "SELINUX_ENFORCED" -> copy(selinuxEnforced = value.asNullableBool())
            "PID_CONTEXT_MATCHES_CURRENT" -> copy(pidContextMatchesCurrent = value.asNullableBool())
            "PROC_SELF_CONTEXT_MATCHES_CURRENT" -> copy(procSelfContextMatchesCurrent = value.asNullableBool())
            "DYNTRANSITION_CHECK_PASSED" -> copy(dyntransitionCheckPassed = value.asNullableBool())
            "CARRIER_CONTROL_VALID" -> copy(carrierControlValid = value.asNullableBool())
            "NEGATIVE_CONTROL_REJECTED" -> copy(negativeControlRejected = value.asNullableBool())
            "FILE_CONTROL_VALID" -> copy(fileControlValid = value.asNullableBool())
            "FILE_NEGATIVE_CONTROL_REJECTED" -> copy(fileNegativeControlRejected = value.asNullableBool())
            "ORACLE_CONTROLS_PASSED" -> copy(oracleControlsPassed = value.asBool())
            "KSU_RESULTS_STABLE" -> copy(ksuResultsStable = value.asBool())
            "QUERY_METHOD" -> copy(queryMethod = value.decodeValue())
            "KSU_DOMAIN_VALID" -> copy(ksuDomainValid = value.asNullableBool())
            "KSU_FILE_VALID" -> copy(ksuFileValid = value.asNullableBool())
            "BIT_PAIR" -> copy(bitPair = value.decodeValue())
            "DIRTY_POLICY_AVAILABLE" -> copy(dirtyPolicyAvailable = value.asBool())
            "DIRTY_POLICY_PROBE_ATTEMPTED" -> copy(dirtyPolicyProbeAttempted = value.asBool())
            "DIRTY_POLICY_CARRIER_CONTEXT" -> copy(dirtyPolicyCarrierContext = value.decodeValue())
            "DIRTY_POLICY_CARRIER_MATCHES_EXPECTED" -> copy(dirtyPolicyCarrierMatchesExpected = value.asBool())
            "DIRTY_POLICY_CONTROLS_PASSED" -> copy(dirtyPolicyControlsPassed = value.asBool())
            "DIRTY_POLICY_STABLE" -> copy(dirtyPolicyStable = value.asBool())
            "DIRTY_POLICY_QUERY_METHOD" -> copy(dirtyPolicyQueryMethod = value.decodeValue())
            "DIRTY_POLICY_ACCESS_CONTROL_ALLOWED" -> copy(dirtyPolicyAccessControlAllowed = value.asNullableBool())
            "DIRTY_POLICY_NEGATIVE_CONTROL_REJECTED" -> copy(dirtyPolicyNegativeControlRejected = value.asNullableBool())
            "DIRTY_POLICY_SYSTEM_SERVER_EXECMEM_ALLOWED" -> copy(dirtyPolicySystemServerExecmemAllowed = value.asNullableBool())
            "DIRTY_POLICY_FSCK_SYS_ADMIN_ALLOWED" -> copy(dirtyPolicyFsckSysAdminAllowed = value.asNullableBool())
            "DIRTY_POLICY_SHELL_SU_TRANSITION_ALLOWED" -> copy(dirtyPolicyShellSuTransitionAllowed = value.asNullableBool())
            "DIRTY_POLICY_ADBD_ADBROOT_BINDER_CALL_ALLOWED" -> copy(dirtyPolicyAdbdAdbrootBinderCallAllowed = value.asNullableBool())
            "DIRTY_POLICY_MAGISK_BINDER_CALL_ALLOWED" -> copy(dirtyPolicyMagiskBinderCallAllowed = value.asNullableBool())
            "DIRTY_POLICY_KSU_FILE_READ_ALLOWED" -> copy(dirtyPolicyKsuFileReadAllowed = value.asNullableBool())
            "DIRTY_POLICY_LSPOSED_FILE_READ_ALLOWED" -> copy(dirtyPolicyLsposedFileReadAllowed = value.asNullableBool())
            "DIRTY_POLICY_MAGISK_DROIDSPACESD_TRANSITION_ALLOWED" -> copy(dirtyPolicyMagiskDroidspacesdTransitionAllowed = value.asNullableBool())
            "DIRTY_POLICY_SU_DROIDSPACESD_TRANSITION_ALLOWED" -> copy(dirtyPolicySuDroidspacesdTransitionAllowed = value.asNullableBool())
            "DIRTY_POLICY_SYSTEM_SERVER_DROIDSPACESD_BINDER_CALL_ALLOWED" -> copy(dirtyPolicySystemServerDroidspacesdBinderCallAllowed = value.asNullableBool())
            "DIRTY_POLICY_MSD_APP_DAEMON_CONNECT_ALLOWED" -> copy(dirtyPolicyMsdAppDaemonConnectAllowed = value.asNullableBool())
            "DIRTY_POLICY_MSD_DAEMON_SELF_CONNECT_ALLOWED" -> copy(dirtyPolicyMsdDaemonSelfConnectAllowed = value.asNullableBool())
            "DIRTY_POLICY_MSD_DAEMON_SELINUXFS_READ_ALLOWED" -> copy(dirtyPolicyMsdDaemonSelinuxfsReadAllowed = value.asNullableBool())
            "DIRTY_POLICY_MSD_DAEMON_CONFIGFS_DIR_SEARCH_ALLOWED" -> copy(dirtyPolicyMsdDaemonConfigfsDirSearchAllowed = value.asNullableBool())
            "DIRTY_POLICY_MSD_DAEMON_CONFIGFS_FILE_WRITE_ALLOWED" -> copy(dirtyPolicyMsdDaemonConfigfsFileWriteAllowed = value.asNullableBool())
            "DIRTY_POLICY_XPOSED_DATA_FILE_READ_ALLOWED" -> copy(dirtyPolicyXposedDataFileReadAllowed = value.asNullableBool())
            "DIRTY_POLICY_ZYGOTE_ADB_DATA_SEARCH_ALLOWED" -> copy(dirtyPolicyZygoteAdbDataSearchAllowed = value.asNullableBool())
            "DIRTY_POLICY_FAILURE_REASON" -> copy(dirtyPolicyFailureReason = value.decodeValue())
            "JAVA_DIRTY_POLICY_AVAILABLE" -> copy(javaDirtyPolicyAvailable = value.asBool())
            "JAVA_DIRTY_POLICY_PROBE_ATTEMPTED" -> copy(javaDirtyPolicyProbeAttempted = value.asBool())
            "JAVA_DIRTY_POLICY_CARRIER_CONTEXT" -> copy(javaDirtyPolicyCarrierContext = value.decodeValue())
            "JAVA_DIRTY_POLICY_CARRIER_MATCHES_EXPECTED" -> copy(javaDirtyPolicyCarrierMatchesExpected = value.asBool())
            "JAVA_DIRTY_POLICY_CONTROLS_PASSED" -> copy(javaDirtyPolicyControlsPassed = value.asBool())
            "JAVA_DIRTY_POLICY_STABLE" -> copy(javaDirtyPolicyStable = value.asBool())
            "JAVA_DIRTY_POLICY_QUERY_METHOD" -> copy(javaDirtyPolicyQueryMethod = value.decodeValue())
            "JAVA_DIRTY_POLICY_ACCESS_CONTROL_ALLOWED" -> copy(javaDirtyPolicyAccessControlAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_NEGATIVE_CONTROL_REJECTED" -> copy(javaDirtyPolicyNegativeControlRejected = value.asNullableBool())
            "JAVA_DIRTY_POLICY_SYSTEM_SERVER_EXECMEM_ALLOWED" -> copy(javaDirtyPolicySystemServerExecmemAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_FSCK_SYS_ADMIN_ALLOWED" -> copy(javaDirtyPolicyFsckSysAdminAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_SHELL_SU_TRANSITION_ALLOWED" -> copy(javaDirtyPolicyShellSuTransitionAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_ADBD_ADBROOT_BINDER_CALL_ALLOWED" -> copy(javaDirtyPolicyAdbdAdbrootBinderCallAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_MAGISK_BINDER_CALL_ALLOWED" -> copy(javaDirtyPolicyMagiskBinderCallAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_KSU_FILE_READ_ALLOWED" -> copy(javaDirtyPolicyKsuFileReadAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_LSPOSED_FILE_READ_ALLOWED" -> copy(javaDirtyPolicyLsposedFileReadAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_MAGISK_DROIDSPACESD_TRANSITION_ALLOWED" -> copy(javaDirtyPolicyMagiskDroidspacesdTransitionAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_SU_DROIDSPACESD_TRANSITION_ALLOWED" -> copy(javaDirtyPolicySuDroidspacesdTransitionAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_SYSTEM_SERVER_DROIDSPACESD_BINDER_CALL_ALLOWED" -> copy(javaDirtyPolicySystemServerDroidspacesdBinderCallAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_MSD_APP_DAEMON_CONNECT_ALLOWED" -> copy(javaDirtyPolicyMsdAppDaemonConnectAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_MSD_DAEMON_SELF_CONNECT_ALLOWED" -> copy(javaDirtyPolicyMsdDaemonSelfConnectAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_MSD_DAEMON_SELINUXFS_READ_ALLOWED" -> copy(javaDirtyPolicyMsdDaemonSelinuxfsReadAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_MSD_DAEMON_CONFIGFS_DIR_SEARCH_ALLOWED" -> copy(javaDirtyPolicyMsdDaemonConfigfsDirSearchAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_MSD_DAEMON_CONFIGFS_FILE_WRITE_ALLOWED" -> copy(javaDirtyPolicyMsdDaemonConfigfsFileWriteAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_XPOSED_DATA_FILE_READ_ALLOWED" -> copy(javaDirtyPolicyXposedDataFileReadAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_ZYGOTE_ADB_DATA_SEARCH_ALLOWED" -> copy(javaDirtyPolicyZygoteAdbDataSearchAllowed = value.asNullableBool())
            "JAVA_DIRTY_POLICY_FAILURE_REASON" -> copy(javaDirtyPolicyFailureReason = value.decodeValue())
            "POLICYLOAD_SEQNO_AVAILABLE" -> copy(policyloadSeqnoAvailable = value.asBool())
            "POLICYLOAD_SEQNO_PROBE_ATTEMPTED" -> copy(policyloadSeqnoProbeAttempted = value.asBool())
            "POLICYLOAD_SEQNO_STATE" -> copy(policyloadSeqnoState = value.decodeValue())
            "POLICYLOAD_SEQNO_CARRIER_CONTEXT" -> copy(policyloadSeqnoCarrierContext = value.decodeValue())
            "POLICYLOAD_SEQNO_STATUS_SEQUENCE" -> copy(policyloadSeqnoStatusSequence = value.toLongOrNull())
            "POLICYLOAD_SEQNO_STATUS_POLICYLOAD" -> copy(policyloadSeqnoStatusPolicyload = value.toLongOrNull())
            "POLICYLOAD_SEQNO_ACCESS_SEQNO" -> copy(policyloadSeqnoAccessSeqno = value.toLongOrNull())
            "POLICYLOAD_SEQNO_PROCESS_CLASS" -> copy(policyloadSeqnoProcessClass = value.toIntOrNull())
            "POLICYLOAD_SEQNO_FAILURE_REASON" -> copy(policyloadSeqnoFailureReason = value.decodeValue())
            "PROC_ATTR_CURRENT_PROBE_ATTEMPTED" -> copy(procAttrCurrentProbeAttempted = value.asBool())
            "PROC_ATTR_CURRENT_FAILURE_REASON" -> copy(procAttrCurrentFailureReason = value.decodeValue())
            "FAILURE_REASON" -> copy(failureReason = value.decodeValue())
            else -> this
        }
    }

    private fun String.asBool(): Boolean {
        return this == "1" || equals("true", ignoreCase = true)
    }

    private fun String.asNullableBool(): Boolean? {
        if (isBlank() || equals("unknown", ignoreCase = true)) {
            return null
        }
        return asBool()
    }

    private fun String.decodeValue(): String {
        return buildString(length) {
            var index = 0
            while (index < this@decodeValue.length) {
                val current = this@decodeValue[index]
                if (current == '\\' && index + 1 < this@decodeValue.length) {
                    when (this@decodeValue[index + 1]) {
                        'n' -> {
                            append('\n')
                            index += 2
                            continue
                        }

                        'r' -> {
                            append('\r')
                            index += 2
                            continue
                        }

                        't' -> {
                            append('\t')
                            index += 2
                            continue
                        }

                        '\\' -> {
                            append('\\')
                            index += 2
                            continue
                        }
                    }
                }
                append(current)
                index += 1
            }
        }
    }

    private external fun nativeCollectContextValiditySnapshotInternal(): String

    companion object {
        @Volatile
        private var preloadedRawData: String? = null

        private val nativeLoaded = runCatching { System.loadLibrary("duckdetector") }.isSuccess

        @JvmStatic
        val isNativeLibraryLoaded: Boolean
            get() = nativeLoaded

        @JvmStatic
        fun nativeCollectContextValiditySnapshot(): String {
            return SelinuxContextValidityBridge().nativeCollectContextValiditySnapshotInternal()
        }

        @JvmStatic
        fun setPreloadedRawData(raw: String) {
            preloadedRawData = raw
        }

        @JvmStatic
        internal fun consumePreloadedRawDataForCarrier(): String? {
            return consumePreloadedRawData()
        }

        @JvmStatic
        internal fun clearPreloadedRawDataForTests() {
            preloadedRawData = null
        }

        private fun consumePreloadedRawData(): String? {
            val raw = preloadedRawData
            preloadedRawData = null
            return raw
        }
    }
}
