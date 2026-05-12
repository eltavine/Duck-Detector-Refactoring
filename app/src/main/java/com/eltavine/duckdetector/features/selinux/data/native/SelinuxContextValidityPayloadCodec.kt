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

internal object SelinuxContextValidityPayloadCodec {

    fun encode(snapshot: SelinuxContextValiditySnapshot): String {
        return buildString {
            append("AVAILABLE=").append(if (snapshot.available) '1' else '0').append('\n')
            append("PROBE_ATTEMPTED=").append(if (snapshot.probeAttempted) '1' else '0')
                .append('\n')
            snapshot.carrierContext?.takeIf { it.isNotEmpty() }?.let {
                append("CARRIER_CONTEXT=").append(escapeValue(it)).append('\n')
            }
            append("CARRIER_MATCHES_EXPECTED=")
                .append(if (snapshot.carrierMatchesExpected) '1' else '0')
                .append('\n')
            snapshot.selinuxEnabled?.let {
                append("SELINUX_ENABLED=").append(if (it) '1' else '0').append('\n')
            }
            snapshot.selinuxEnforced?.let {
                append("SELINUX_ENFORCED=").append(if (it) '1' else '0').append('\n')
            }
            snapshot.pidContextMatchesCurrent?.let {
                append("PID_CONTEXT_MATCHES_CURRENT=").append(if (it) '1' else '0').append('\n')
            }
            snapshot.procSelfContextMatchesCurrent?.let {
                append("PROC_SELF_CONTEXT_MATCHES_CURRENT=").append(if (it) '1' else '0')
                    .append('\n')
            }
            snapshot.dyntransitionCheckPassed?.let {
                append("DYNTRANSITION_CHECK_PASSED=").append(if (it) '1' else '0').append('\n')
            }
            snapshot.carrierControlValid?.let {
                append("CARRIER_CONTROL_VALID=").append(if (it) '1' else '0').append('\n')
            }
            snapshot.negativeControlRejected?.let {
                append("NEGATIVE_CONTROL_REJECTED=").append(if (it) '1' else '0').append('\n')
            }
            snapshot.fileControlValid?.let {
                append("FILE_CONTROL_VALID=").append(if (it) '1' else '0').append('\n')
            }
            snapshot.fileNegativeControlRejected?.let {
                append("FILE_NEGATIVE_CONTROL_REJECTED=").append(if (it) '1' else '0')
                    .append('\n')
            }
            append("ORACLE_CONTROLS_PASSED=")
                .append(if (snapshot.oracleControlsPassed) '1' else '0')
                .append('\n')
            append("KSU_RESULTS_STABLE=").append(if (snapshot.ksuResultsStable) '1' else '0')
                .append('\n')
            snapshot.queryMethod.takeIf { it.isNotEmpty() }?.let {
                append("QUERY_METHOD=").append(escapeValue(it)).append('\n')
            }
            snapshot.ksuDomainValid?.let {
                append("KSU_DOMAIN_VALID=").append(if (it) '1' else '0').append('\n')
            }
            snapshot.ksuFileValid?.let {
                append("KSU_FILE_VALID=").append(if (it) '1' else '0').append('\n')
            }
            snapshot.bitPair?.takeIf { it.isNotEmpty() }?.let {
                append("BIT_PAIR=").append(escapeValue(it)).append('\n')
            }
            append("DIRTY_POLICY_AVAILABLE=")
                .append(if (snapshot.dirtyPolicyAvailable) '1' else '0')
                .append('\n')
            append("DIRTY_POLICY_PROBE_ATTEMPTED=")
                .append(if (snapshot.dirtyPolicyProbeAttempted) '1' else '0')
                .append('\n')
            snapshot.dirtyPolicyCarrierContext?.takeIf { it.isNotEmpty() }?.let {
                append("DIRTY_POLICY_CARRIER_CONTEXT=").append(escapeValue(it)).append('\n')
            }
            append("DIRTY_POLICY_CARRIER_MATCHES_EXPECTED=")
                .append(if (snapshot.dirtyPolicyCarrierMatchesExpected) '1' else '0')
                .append('\n')
            append("DIRTY_POLICY_CONTROLS_PASSED=")
                .append(if (snapshot.dirtyPolicyControlsPassed) '1' else '0')
                .append('\n')
            append("DIRTY_POLICY_STABLE=")
                .append(if (snapshot.dirtyPolicyStable) '1' else '0')
                .append('\n')
            snapshot.dirtyPolicyQueryMethod.takeIf { it.isNotEmpty() }?.let {
                append("DIRTY_POLICY_QUERY_METHOD=").append(escapeValue(it)).append('\n')
            }
            snapshot.dirtyPolicyAccessControlAllowed?.let {
                append("DIRTY_POLICY_ACCESS_CONTROL_ALLOWED=")
                    .append(if (it) '1' else '0')
                    .append('\n')
            }
            snapshot.dirtyPolicyNegativeControlRejected?.let {
                append("DIRTY_POLICY_NEGATIVE_CONTROL_REJECTED=")
                    .append(if (it) '1' else '0')
                    .append('\n')
            }
            snapshot.dirtyPolicySystemServerExecmemAllowed?.let {
                append("DIRTY_POLICY_SYSTEM_SERVER_EXECMEM_ALLOWED=")
                    .append(if (it) '1' else '0')
                    .append('\n')
            }
            snapshot.dirtyPolicyFsckSysAdminAllowed?.let {
                append("DIRTY_POLICY_FSCK_SYS_ADMIN_ALLOWED=")
                    .append(if (it) '1' else '0')
                    .append('\n')
            }
            snapshot.dirtyPolicyShellSuTransitionAllowed?.let {
                append("DIRTY_POLICY_SHELL_SU_TRANSITION_ALLOWED=")
                    .append(if (it) '1' else '0')
                    .append('\n')
            }
            snapshot.dirtyPolicyAdbdAdbrootBinderCallAllowed?.let {
                append("DIRTY_POLICY_ADBD_ADBROOT_BINDER_CALL_ALLOWED=")
                    .append(if (it) '1' else '0')
                    .append('\n')
            }
            snapshot.dirtyPolicyMagiskBinderCallAllowed?.let {
                append("DIRTY_POLICY_MAGISK_BINDER_CALL_ALLOWED=")
                    .append(if (it) '1' else '0')
                    .append('\n')
            }
            snapshot.dirtyPolicyKsuFileReadAllowed?.let {
                append("DIRTY_POLICY_KSU_FILE_READ_ALLOWED=")
                    .append(if (it) '1' else '0')
                    .append('\n')
            }
            snapshot.dirtyPolicyLsposedFileReadAllowed?.let {
                append("DIRTY_POLICY_LSPOSED_FILE_READ_ALLOWED=")
                    .append(if (it) '1' else '0')
                    .append('\n')
            }
            snapshot.dirtyPolicyXposedDataFileReadAllowed?.let {
                append("DIRTY_POLICY_XPOSED_DATA_FILE_READ_ALLOWED=")
                    .append(if (it) '1' else '0')
                    .append('\n')
            }
            snapshot.dirtyPolicyZygoteAdbDataSearchAllowed?.let {
                append("DIRTY_POLICY_ZYGOTE_ADB_DATA_SEARCH_ALLOWED=")
                    .append(if (it) '1' else '0')
                    .append('\n')
            }
            snapshot.dirtyPolicyFailureReason?.takeIf { it.isNotEmpty() }?.let {
                append("DIRTY_POLICY_FAILURE_REASON=").append(escapeValue(it)).append('\n')
            }
            snapshot.dirtyPolicyNotes.forEach { note ->
                append("DIRTY_POLICY_NOTE=").append(escapeValue(note)).append('\n')
            }
            append("PROC_ATTR_CURRENT_PROBE_ATTEMPTED=")
                .append(if (snapshot.procAttrCurrentProbeAttempted) '1' else '0')
                .append('\n')
            snapshot.procAttrCurrentResults.forEach { result ->
                append("PROC_ATTR_CURRENT_RESULT=")
                    .append(escapeValue(SelinuxProcAttrCurrentPayloadCodec.encode(result)))
                    .append('\n')
            }
            snapshot.procAttrCurrentFailureReason?.takeIf { it.isNotEmpty() }?.let {
                append("PROC_ATTR_CURRENT_FAILURE_REASON=")
                    .append(escapeValue(it))
                    .append('\n')
            }
            snapshot.failureReason?.takeIf { it.isNotEmpty() }?.let {
                append("FAILURE_REASON=").append(escapeValue(it)).append('\n')
            }
            snapshot.notes.forEach { note ->
                append("NOTE=").append(escapeValue(note)).append('\n')
            }
        }
    }

    private fun escapeValue(value: String): String {
        return buildString(value.length) {
            value.forEach { ch ->
                when (ch) {
                    '\\' -> append("\\\\")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(ch)
                }
            }
        }
    }
}
