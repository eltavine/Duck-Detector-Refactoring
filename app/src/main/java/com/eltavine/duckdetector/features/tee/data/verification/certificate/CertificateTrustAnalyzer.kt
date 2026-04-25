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

import com.eltavine.duckdetector.features.tee.domain.TeeTrustRoot
import java.security.cert.X509Certificate

class CertificateTrustAnalyzer(
    private val googleRoots: GoogleAttestationRootStore,
) {

    fun inspect(chain: List<X509Certificate>): CertificateTrustResult {
        if (chain.isEmpty()) {
            return CertificateTrustResult()
        }
        val root = chain.last()
        val chainSignatureValid = verifyChainSignatures(chain)
        val rootFingerprint = root.publicKey.encoded.sha256()
        val googleRootMatched = googleRoots.contains(root)
        val issuerMismatches = chain.zipWithNext().mapIndexedNotNull { index, (current, next) ->
            if (current.issuerX500Principal == next.subjectX500Principal) {
                null
            } else {
                "Certificate ${index + 1} issuer does not match certificate ${index + 2} subject."
            }
        }
        val expiredCertificates = chain.mapIndexedNotNull { index, cert ->
            runCatching { cert.checkValidity() }.exceptionOrNull()?.let { throwable ->
                "Certificate ${index + 1} validity issue: ${throwable.javaClass.simpleName}."
            }
        }
        val trustRoot = when {
            googleRootMatched -> TeeTrustRoot.GOOGLE
            chain.any(::looksLikeAospAttestationCert) -> TeeTrustRoot.AOSP
            else -> TeeTrustRoot.FACTORY
        }
        return CertificateTrustResult(
            trustRoot = trustRoot,
            chainLength = chain.size,
            chainSignatureValid = chainSignatureValid,
            rootFingerprint = rootFingerprint,
            googleRootMatched = googleRootMatched,
            issuerMismatches = issuerMismatches,
            expiredCertificates = expiredCertificates,
        )
    }

    private fun verifyChainSignatures(chain: List<X509Certificate>): Boolean {
        return runCatching {
            chain.zipWithNext().forEach { (cert, issuer) ->
                cert.verify(issuer.publicKey)
            }
            chain.last().verify(chain.last().publicKey)
        }.isSuccess
    }

    private fun looksLikeAospAttestationCert(cert: X509Certificate): Boolean {
        val subject = cert.subjectX500Principal.name
        val issuer = cert.issuerX500Principal.name
        return AOSP_PATTERNS.any { pattern ->
            subject.contains(pattern, ignoreCase = true) || issuer.contains(
                pattern,
                ignoreCase = true
            )
        }
    }

    private fun ByteArray.sha256(): String {
        return java.security.MessageDigest.getInstance("SHA-256")
            .digest(this)
            .joinToString(separator = "") { byte -> "%02x".format(byte) }
    }

    companion object {
        private val AOSP_PATTERNS = listOf(
            "Android Keystore Software Attestation",
            "Software Attestation",
            "CN=Android, O=Android, C=US",
        )
    }
}

data class CertificateTrustResult(
    val trustRoot: TeeTrustRoot = TeeTrustRoot.UNKNOWN,
    val chainLength: Int = 0,
    val chainSignatureValid: Boolean = false,
    val rootFingerprint: String? = null,
    val googleRootMatched: Boolean = false,
    val issuerMismatches: List<String> = emptyList(),
    val expiredCertificates: List<String> = emptyList(),
)
