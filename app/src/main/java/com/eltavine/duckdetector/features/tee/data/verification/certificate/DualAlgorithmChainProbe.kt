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

class DualAlgorithmChainProbe(
    private val trustAnalyzer: CertificateTrustAnalyzer,
) {

    fun inspect(
        rsaChain: List<X509Certificate>,
        ecChain: List<X509Certificate>,
    ): DualAlgorithmChainResult {
        if (rsaChain.isEmpty() || ecChain.isEmpty()) {
            return DualAlgorithmChainResult(
                mismatchDetected = false,
                detail = "Dual-algorithm comparison could not collect both RSA and EC attestation chains.",
            )
        }
        val rsaTrust = trustAnalyzer.inspect(rsaChain)
        val ecTrust = trustAnalyzer.inspect(ecChain)
        val issuerMismatch =
            rsaChain.first().issuerX500Principal != ecChain.first().issuerX500Principal
        val trustRootMismatch = rsaTrust.trustRoot != ecTrust.trustRoot
        val chainLengthMismatch = rsaChain.size != ecChain.size
        return DualAlgorithmChainResult(
            mismatchDetected = issuerMismatch || trustRootMismatch || chainLengthMismatch,
            detail = buildString {
                append("RSA root=")
                append(rsaTrust.trustRoot)
                append(", EC root=")
                append(ecTrust.trustRoot)
                append(", RSA len=")
                append(rsaChain.size)
                append(", EC len=")
                append(ecChain.size)
            },
            trustRootMismatch = trustRootMismatch,
            issuerMismatch = issuerMismatch,
            chainLengthMismatch = chainLengthMismatch,
        )
    }
}

data class DualAlgorithmChainResult(
    val mismatchDetected: Boolean,
    val detail: String,
    val trustRootMismatch: Boolean = false,
    val issuerMismatch: Boolean = false,
    val chainLengthMismatch: Boolean = false,
)
