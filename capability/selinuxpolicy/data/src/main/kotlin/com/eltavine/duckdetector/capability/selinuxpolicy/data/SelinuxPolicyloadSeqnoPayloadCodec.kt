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

import com.eltavine.duckdetector.core.native.NativePayloadCodec

internal fun StringBuilder.appendPolicyloadSeqno(snapshot: SelinuxContextValiditySnapshot) {
    append("POLICYLOAD_SEQNO_AVAILABLE=")
        .append(if (snapshot.policyloadSeqnoAvailable) '1' else '0')
        .append('\n')
    append("POLICYLOAD_SEQNO_PROBE_ATTEMPTED=")
        .append(if (snapshot.policyloadSeqnoProbeAttempted) '1' else '0')
        .append('\n')
    snapshot.policyloadSeqnoState?.takeIf { it.isNotEmpty() }?.let {
        append("POLICYLOAD_SEQNO_STATE=").append(NativePayloadCodec.encodeValue(it)).append('\n')
    }
    snapshot.policyloadSeqnoCarrierContext?.takeIf { it.isNotEmpty() }?.let {
        append("POLICYLOAD_SEQNO_CARRIER_CONTEXT=").append(NativePayloadCodec.encodeValue(it)).append('\n')
    }
    snapshot.policyloadSeqnoStatusSequence?.let {
        append("POLICYLOAD_SEQNO_STATUS_SEQUENCE=").append(it).append('\n')
    }
    snapshot.policyloadSeqnoStatusPolicyload?.let {
        append("POLICYLOAD_SEQNO_STATUS_POLICYLOAD=").append(it).append('\n')
    }
    snapshot.policyloadSeqnoAccessSeqno?.let {
        append("POLICYLOAD_SEQNO_ACCESS_SEQNO=").append(it).append('\n')
    }
    snapshot.policyloadSeqnoProcessClass?.let {
        append("POLICYLOAD_SEQNO_PROCESS_CLASS=").append(it).append('\n')
    }
    snapshot.policyloadSeqnoFailureReason?.takeIf { it.isNotEmpty() }?.let {
        append("POLICYLOAD_SEQNO_FAILURE_REASON=").append(NativePayloadCodec.encodeValue(it)).append('\n')
    }
    snapshot.policyloadSeqnoNotes.forEach { note ->
        append("POLICYLOAD_SEQNO_NOTE=").append(NativePayloadCodec.encodeValue(note)).append('\n')
    }
}
