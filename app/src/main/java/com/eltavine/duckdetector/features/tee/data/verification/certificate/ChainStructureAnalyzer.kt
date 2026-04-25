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

package com.eltavine.duckdetector.features.tee.data.verification.certificate

import java.security.cert.X509Certificate

class ChainStructureAnalyzer {

    fun inspect(chain: List<X509Certificate>): ChainStructureResult {
        if (chain.isEmpty()) {
            return ChainStructureResult(detail = "No certificate chain was available.")
        }
        val issuerMismatches = chain.zipWithNext().mapIndexedNotNull { index, (current, next) ->
            if (current.issuerX500Principal == next.subjectX500Principal) {
                null
            } else {
                "Cert ${index + 1} issuer does not match cert ${index + 2} subject."
            }
        }
        val expiredCertificates = chain.mapIndexedNotNull { index, cert ->
            runCatching { cert.checkValidity() }.exceptionOrNull()?.let { throwable ->
                "Cert ${index + 1}: ${throwable.javaClass.simpleName}"
            }
        }
        val attestationIndices =
            chain.indices.filter { chain[it].getExtensionValue(KEY_ATTESTATION_OID) != null }
        val trustedAttestationIndex = attestationIndices.lastOrNull()
        val provisioningIndex =
            chain.indices.filter { chain[it].getExtensionValue(PROVISIONING_INFO_OID) != null }
                .lastOrNull()
        val chainLengthAnomaly = chain.size !in MIN_CHAIN_LENGTH..MAX_CHAIN_LENGTH
        val provisioningConsistencyIssue = provisioningIndex != null &&
                trustedAttestationIndex != null &&
                provisioningIndex != trustedAttestationIndex + 1
        return ChainStructureResult(
            chainLength = chain.size,
            chainLengthAnomaly = chainLengthAnomaly,
            trustedAttestationIndex = trustedAttestationIndex,
            attestationExtensionCount = attestationIndices.size,
            hasMultipleAttestationExtensions = attestationIndices.size > 1,
            provisioningIndex = provisioningIndex,
            provisioningConsistencyIssue = provisioningConsistencyIssue,
            issuerMismatches = issuerMismatches,
            expiredCertificates = expiredCertificates,
            detail = buildString {
                append("len=")
                append(chain.size)
                append(", attestExt=")
                append(attestationIndices.size)
                trustedAttestationIndex?.let {
                    append(", trustedIndex=")
                    append(it)
                }
                provisioningIndex?.let {
                    append(", provisioningIndex=")
                    append(it)
                }
            },
        )
    }

    companion object {
        private const val KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
        private const val PROVISIONING_INFO_OID = "1.3.6.1.4.1.11129.2.1.30"
        private const val MIN_CHAIN_LENGTH = 2
        private const val MAX_CHAIN_LENGTH = 6
    }
}

data class ChainStructureResult(
    val chainLength: Int = 0,
    val chainLengthAnomaly: Boolean = false,
    val trustedAttestationIndex: Int? = null,
    val attestationExtensionCount: Int = 0,
    val hasMultipleAttestationExtensions: Boolean = false,
    val provisioningIndex: Int? = null,
    val provisioningConsistencyIssue: Boolean = false,
    val issuerMismatches: List<String> = emptyList(),
    val expiredCertificates: List<String> = emptyList(),
    val detail: String,
)
