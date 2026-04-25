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

class AttestationExtensionProbe {

    fun inspect(chain: List<X509Certificate>): AttestationExtensionResult {
        val attestationCount = chain.count { it.getExtensionValue(KEY_ATTESTATION_OID) != null }
        return AttestationExtensionResult(
            extensionCount = attestationCount,
            hasMultipleAttestationExtensions = attestationCount > 1,
            detail = if (attestationCount <= 1) {
                "Attestation extension appears exactly once in the chain."
            } else {
                "Attestation extension appears $attestationCount times in the chain."
            },
        )
    }

    companion object {
        private const val KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
    }
}

data class AttestationExtensionResult(
    val extensionCount: Int,
    val hasMultipleAttestationExtensions: Boolean,
    val detail: String,
)
