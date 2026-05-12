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

package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValidityBridge
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValiditySnapshot

enum class SelinuxContextValidityState {
    CLEAN,
    KSU_PRESENT,
    AMBIGUOUS,
    INCONSISTENT,
    UNAVAILABLE,
}

data class SelinuxContextValidityProbeResult(
    val state: SelinuxContextValidityState,
    val available: Boolean,
    val probeAttempted: Boolean,
    val carrierContext: String?,
    val carrierMatchesExpected: Boolean,
    val selinuxEnabled: Boolean?,
    val selinuxEnforced: Boolean?,
    val pidContextMatchesCurrent: Boolean?,
    val procSelfContextMatchesCurrent: Boolean?,
    val dyntransitionCheckPassed: Boolean?,
    val carrierControlValid: Boolean?,
    val negativeControlRejected: Boolean?,
    val fileControlValid: Boolean?,
    val fileNegativeControlRejected: Boolean?,
    val oracleControlsPassed: Boolean,
    val ksuResultsStable: Boolean,
    val queryMethod: String,
    val ksuDomainValid: Boolean?,
    val ksuFileValid: Boolean?,
    val bitPair: String?,
    val dirtyPolicyAvailable: Boolean,
    val dirtyPolicyProbeAttempted: Boolean,
    val dirtyPolicyCarrierContext: String?,
    val dirtyPolicyCarrierMatchesExpected: Boolean,
    val dirtyPolicyControlsPassed: Boolean,
    val dirtyPolicyStable: Boolean,
    val dirtyPolicyQueryMethod: String,
    val dirtyPolicyAccessControlAllowed: Boolean?,
    val dirtyPolicyNegativeControlRejected: Boolean?,
    val dirtyPolicySystemServerExecmemAllowed: Boolean?,
    val dirtyPolicyFsckSysAdminAllowed: Boolean?,
    val dirtyPolicyShellSuTransitionAllowed: Boolean?,
    val dirtyPolicyAdbdAdbrootBinderCallAllowed: Boolean?,
    val dirtyPolicyMagiskBinderCallAllowed: Boolean?,
    val dirtyPolicyKsuFileReadAllowed: Boolean?,
    val dirtyPolicyLsposedFileReadAllowed: Boolean?,
    val dirtyPolicyXposedDataFileReadAllowed: Boolean?,
    val dirtyPolicyZygoteAdbDataSearchAllowed: Boolean?,
    val dirtyPolicyFailureReason: String?,
    val dirtyPolicyNotes: List<String>,
    val procAttrCurrentProbeAttempted: Boolean,
    val procAttrCurrentResults: List<SelinuxProcAttrCurrentResult>,
    val procAttrCurrentFailureReason: String?,
    val failureReason: String?,
    val notes: List<String>,
)

class SelinuxContextValidityProbe(
    private val nativeBridge: SelinuxContextValidityBridge = SelinuxContextValidityBridge(),
) {

    fun inspect(): SelinuxContextValidityProbeResult {
        return nativeBridge.collectSnapshot().toProbeResult()
    }

    fun interpret(snapshot: SelinuxContextValiditySnapshot): SelinuxContextValidityProbeResult {
        return snapshot.toProbeResult()
    }

    internal fun SelinuxContextValiditySnapshot.toProbeResult(): SelinuxContextValidityProbeResult {
        val state = when {
            !available -> SelinuxContextValidityState.UNAVAILABLE
            !carrierMatchesExpected -> SelinuxContextValidityState.UNAVAILABLE
            !probeAttempted -> SelinuxContextValidityState.UNAVAILABLE
            !oracleControlsPassed -> SelinuxContextValidityState.INCONSISTENT
            !ksuResultsStable -> SelinuxContextValidityState.INCONSISTENT
            ksuDomainValid == null || ksuFileValid == null -> SelinuxContextValidityState.UNAVAILABLE
            ksuDomainValid && ksuFileValid -> SelinuxContextValidityState.KSU_PRESENT
            !ksuDomainValid && !ksuFileValid -> SelinuxContextValidityState.CLEAN
            else -> SelinuxContextValidityState.AMBIGUOUS
        }

        val notes = buildList {
            addAll(this@toProbeResult.notes)
            when (state) {
                SelinuxContextValidityState.CLEAN ->
                    add("Bit pair 00 means both KSU-specific contexts were rejected by live policy.")

                SelinuxContextValidityState.KSU_PRESENT ->
                    add("Bit pair 11 means both KSU-specific contexts were accepted by live policy.")

                SelinuxContextValidityState.AMBIGUOUS ->
                    add("Bit pair 01/10 means the KSU-specific contexts split across live policy checks.")

                SelinuxContextValidityState.INCONSISTENT ->
                    add("Oracle self-test failed, so the KSU-specific context verdict is not trusted.")

                SelinuxContextValidityState.UNAVAILABLE -> Unit
            }
        }.distinct()

        return SelinuxContextValidityProbeResult(
            state = state,
            available = available,
            probeAttempted = probeAttempted,
            carrierContext = carrierContext,
            carrierMatchesExpected = carrierMatchesExpected,
            selinuxEnabled = selinuxEnabled,
            selinuxEnforced = selinuxEnforced,
            pidContextMatchesCurrent = pidContextMatchesCurrent,
            procSelfContextMatchesCurrent = procSelfContextMatchesCurrent,
            dyntransitionCheckPassed = dyntransitionCheckPassed,
            carrierControlValid = carrierControlValid,
            negativeControlRejected = negativeControlRejected,
            fileControlValid = fileControlValid,
            fileNegativeControlRejected = fileNegativeControlRejected,
            oracleControlsPassed = oracleControlsPassed,
            ksuResultsStable = ksuResultsStable,
            queryMethod = queryMethod,
            ksuDomainValid = ksuDomainValid,
            ksuFileValid = ksuFileValid,
            bitPair = bitPair,
            dirtyPolicyAvailable = dirtyPolicyAvailable,
            dirtyPolicyProbeAttempted = dirtyPolicyProbeAttempted,
            dirtyPolicyCarrierContext = dirtyPolicyCarrierContext,
            dirtyPolicyCarrierMatchesExpected = dirtyPolicyCarrierMatchesExpected,
            dirtyPolicyControlsPassed = dirtyPolicyControlsPassed,
            dirtyPolicyStable = dirtyPolicyStable,
            dirtyPolicyQueryMethod = dirtyPolicyQueryMethod,
            dirtyPolicyAccessControlAllowed = dirtyPolicyAccessControlAllowed,
            dirtyPolicyNegativeControlRejected = dirtyPolicyNegativeControlRejected,
            dirtyPolicySystemServerExecmemAllowed = dirtyPolicySystemServerExecmemAllowed,
            dirtyPolicyFsckSysAdminAllowed = dirtyPolicyFsckSysAdminAllowed,
            dirtyPolicyShellSuTransitionAllowed = dirtyPolicyShellSuTransitionAllowed,
            dirtyPolicyAdbdAdbrootBinderCallAllowed = dirtyPolicyAdbdAdbrootBinderCallAllowed,
            dirtyPolicyMagiskBinderCallAllowed = dirtyPolicyMagiskBinderCallAllowed,
            dirtyPolicyKsuFileReadAllowed = dirtyPolicyKsuFileReadAllowed,
            dirtyPolicyLsposedFileReadAllowed = dirtyPolicyLsposedFileReadAllowed,
            dirtyPolicyXposedDataFileReadAllowed = dirtyPolicyXposedDataFileReadAllowed,
            dirtyPolicyZygoteAdbDataSearchAllowed = dirtyPolicyZygoteAdbDataSearchAllowed,
            dirtyPolicyFailureReason = dirtyPolicyFailureReason,
            dirtyPolicyNotes = dirtyPolicyNotes,
            procAttrCurrentProbeAttempted = procAttrCurrentProbeAttempted,
            procAttrCurrentResults = procAttrCurrentResults,
            procAttrCurrentFailureReason = procAttrCurrentFailureReason,
            failureReason = failureReason,
            notes = notes,
        )
    }

    companion object {
        const val METHOD_LABEL = "Context validity oracle"
        const val BITPAIR_CLEAN = "00"
        const val BITPAIR_KSU_PRESENT = "11"
        const val BITPAIR_AMBIGUOUS = "01/10"
        const val BITPAIR_SELF_TEST_FAILED = "Self-test failed"
        const val BITPAIR_UNSUPPORTED = "Unsupported"
    }
}
