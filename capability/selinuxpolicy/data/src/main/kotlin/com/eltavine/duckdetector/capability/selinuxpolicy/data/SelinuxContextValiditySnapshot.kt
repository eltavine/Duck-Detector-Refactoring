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

import com.eltavine.duckdetector.core.native.NativeCollectionStatus

public data class SelinuxContextValiditySnapshot(
    val available: Boolean = false,
    val probeAttempted: Boolean = false,
    val carrierContext: String? = null,
    val carrierMatchesExpected: Boolean = false,
    val selinuxEnabled: Boolean? = null,
    val selinuxEnforced: Boolean? = null,
    val pidContextMatchesCurrent: Boolean? = null,
    val procSelfContextMatchesCurrent: Boolean? = null,
    val dyntransitionCheckPassed: Boolean? = null,
    val carrierControlValid: Boolean? = null,
    val negativeControlRejected: Boolean? = null,
    val fileControlValid: Boolean? = null,
    val fileNegativeControlRejected: Boolean? = null,
    val oracleControlsPassed: Boolean = false,
    val ksuResultsStable: Boolean = false,
    val queryMethod: String = "",
    val ksuDomainValid: Boolean? = null,
    val ksuFileValid: Boolean? = null,
    val bitPair: String? = null,
    val dirtyPolicyAvailable: Boolean = false,
    val dirtyPolicyProbeAttempted: Boolean = false,
    val dirtyPolicyCarrierContext: String? = null,
    val dirtyPolicyCarrierMatchesExpected: Boolean = false,
    val dirtyPolicyControlsPassed: Boolean = false,
    val dirtyPolicyStable: Boolean = false,
    val dirtyPolicyQueryMethod: String = "",
    val dirtyPolicyAccessControlAllowed: Boolean? = null,
    val dirtyPolicyNegativeControlRejected: Boolean? = null,
    val dirtyPolicySystemServerExecmemAllowed: Boolean? = null,
    val dirtyPolicyFsckSysAdminAllowed: Boolean? = null,
    val dirtyPolicyShellSuTransitionAllowed: Boolean? = null,
    val dirtyPolicyAdbdAdbrootBinderCallAllowed: Boolean? = null,
    val dirtyPolicyMagiskBinderCallAllowed: Boolean? = null,
    val dirtyPolicyKsuFileReadAllowed: Boolean? = null,
    val dirtyPolicyLsposedFileReadAllowed: Boolean? = null,
    val dirtyPolicyMagiskDroidspacesdTransitionAllowed: Boolean? = null,
    val dirtyPolicySuDroidspacesdTransitionAllowed: Boolean? = null,
    val dirtyPolicySystemServerDroidspacesdBinderCallAllowed: Boolean? = null,
    val dirtyPolicyMsdAppDaemonConnectAllowed: Boolean? = null,
    val dirtyPolicyMsdDaemonSelfConnectAllowed: Boolean? = null,
    val dirtyPolicyMsdDaemonSelinuxfsReadAllowed: Boolean? = null,
    val dirtyPolicyMsdDaemonConfigfsDirSearchAllowed: Boolean? = null,
    val dirtyPolicyMsdDaemonConfigfsFileWriteAllowed: Boolean? = null,
    val dirtyPolicyXposedDataFileReadAllowed: Boolean? = null,
    val dirtyPolicyZygoteAdbDataSearchAllowed: Boolean? = null,
    val dirtyPolicyFailureReason: String? = null,
    val dirtyPolicyNotes: List<String> = emptyList(),
    val javaDirtyPolicyAvailable: Boolean = false,
    val javaDirtyPolicyProbeAttempted: Boolean = false,
    val javaDirtyPolicyCarrierContext: String? = null,
    val javaDirtyPolicyCarrierMatchesExpected: Boolean = false,
    val javaDirtyPolicyControlsPassed: Boolean = false,
    val javaDirtyPolicyStable: Boolean = false,
    val javaDirtyPolicyQueryMethod: String = "",
    val javaDirtyPolicyAccessControlAllowed: Boolean? = null,
    val javaDirtyPolicyNegativeControlRejected: Boolean? = null,
    val javaDirtyPolicySystemServerExecmemAllowed: Boolean? = null,
    val javaDirtyPolicyFsckSysAdminAllowed: Boolean? = null,
    val javaDirtyPolicyShellSuTransitionAllowed: Boolean? = null,
    val javaDirtyPolicyAdbdAdbrootBinderCallAllowed: Boolean? = null,
    val javaDirtyPolicyMagiskBinderCallAllowed: Boolean? = null,
    val javaDirtyPolicyKsuFileReadAllowed: Boolean? = null,
    val javaDirtyPolicyLsposedFileReadAllowed: Boolean? = null,
    val javaDirtyPolicyMagiskDroidspacesdTransitionAllowed: Boolean? = null,
    val javaDirtyPolicySuDroidspacesdTransitionAllowed: Boolean? = null,
    val javaDirtyPolicySystemServerDroidspacesdBinderCallAllowed: Boolean? = null,
    val javaDirtyPolicyMsdAppDaemonConnectAllowed: Boolean? = null,
    val javaDirtyPolicyMsdDaemonSelfConnectAllowed: Boolean? = null,
    val javaDirtyPolicyMsdDaemonSelinuxfsReadAllowed: Boolean? = null,
    val javaDirtyPolicyMsdDaemonConfigfsDirSearchAllowed: Boolean? = null,
    val javaDirtyPolicyMsdDaemonConfigfsFileWriteAllowed: Boolean? = null,
    val javaDirtyPolicyXposedDataFileReadAllowed: Boolean? = null,
    val javaDirtyPolicyZygoteAdbDataSearchAllowed: Boolean? = null,
    val javaDirtyPolicyFailureReason: String? = null,
    val javaDirtyPolicyNotes: List<String> = emptyList(),
    val policyloadSeqnoAvailable: Boolean = false,
    val policyloadSeqnoProbeAttempted: Boolean = false,
    val policyloadSeqnoState: String? = null,
    val policyloadSeqnoCarrierContext: String? = null,
    val policyloadSeqnoStatusSequence: Long? = null,
    val policyloadSeqnoStatusPolicyload: Long? = null,
    val policyloadSeqnoAccessSeqno: Long? = null,
    val policyloadSeqnoProcessClass: Int? = null,
    val policyloadSeqnoFailureReason: String? = null,
    val policyloadSeqnoNotes: List<String> = emptyList(),
    val procAttrCurrentProbeAttempted: Boolean = false,
    val procAttrCurrentResults: List<SelinuxProcAttrCurrentResult> = emptyList(),
    val procAttrCurrentFailureReason: String? = null,
    val avcLookup: SelinuxAvcLookupSnapshot = SelinuxAvcLookupSnapshot(),
    val failureReason: String? = null,
    val notes: List<String> = emptyList(),
    /**
     * Why this snapshot is or is not usable. [available] alone cannot distinguish "the probe ran and
     * found nothing" from "the probe never ran", so the reason is carried here. [failureReason] holds
     * the same information in the wording the report shows.
     */
    val collection: NativeCollectionStatus = NativeCollectionStatus.Collected,
    val sidtab: SelinuxSidtabSnapshot = SelinuxSidtabSnapshot(),
) {
    /**
     * Whether the native dirty-policy access oracle passed its own checks: it ran in the expected
     * app_zygote carrier, answered the same way on repeated queries, allowed the control edge that
     * stock policy allows and denied the one it denies. Only then does an allowed edge describe the
     * live policy rather than a broken query path.
     */
    public val dirtyPolicyTrusted: Boolean
        get() = dirtyPolicyAvailable && dirtyPolicyProbeAttempted && dirtyPolicyCarrierMatchesExpected &&
            dirtyPolicyStable && dirtyPolicyControlsPassed &&
            dirtyPolicyAccessControlAllowed == true && dirtyPolicyNegativeControlRejected == true

    /** [dirtyPolicyTrusted] for the oracle that queries through android.os.SELinux. */
    public val javaDirtyPolicyTrusted: Boolean
        get() = javaDirtyPolicyAvailable && javaDirtyPolicyProbeAttempted && javaDirtyPolicyCarrierMatchesExpected &&
            javaDirtyPolicyStable && javaDirtyPolicyControlsPassed &&
            javaDirtyPolicyAccessControlAllowed == true && javaDirtyPolicyNegativeControlRejected == true
}
