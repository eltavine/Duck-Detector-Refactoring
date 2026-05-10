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
