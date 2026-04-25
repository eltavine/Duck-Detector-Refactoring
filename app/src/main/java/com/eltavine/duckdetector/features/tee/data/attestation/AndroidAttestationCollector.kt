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

package com.eltavine.duckdetector.features.tee.data.attestation

import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import java.security.SecureRandom
import java.security.cert.X509Certificate

class AndroidAttestationCollector(
    private val parser: AttestationExtensionParser = AttestationExtensionParser(),
) {

    fun collect(useStrongBox: Boolean = false): AttestationSnapshot {
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duckdetector_attest_${System.nanoTime()}"
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        return runCatching {
            val chain = AndroidKeyStoreTools.generateAttestedEcChain(
                keyStore = keyStore,
                alias = alias,
                challenge = challenge,
                useStrongBox = useStrongBox,
            )
            parser.parse(chain, challenge)
        }.getOrElse { throwable ->
            AttestationSnapshot(
                tier = TeeTier.UNKNOWN,
                attestationVersion = null,
                keymasterVersion = null,
                attestationTier = null,
                keymasterTier = null,
                challengeVerified = false,
                challengeSummary = null,
                rootOfTrust = null,
                osVersion = null,
                osPatchLevel = null,
                vendorPatchLevel = null,
                bootPatchLevel = null,
                keyProperties = AttestedKeyProperties(),
                authState = AttestedAuthState(),
                applicationInfo = AttestedApplicationInfo(),
                deviceInfo = AttestedDeviceInfo(),
                deviceUniqueAttestation = false,
                trustedAttestationIndex = null,
                rawCertificates = emptyList(),
                displayCertificates = emptyList(),
                errorMessage = throwable.message ?: "Attestation collection failed",
            )
        }.also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }

    fun collectComparisonChains(useStrongBox: Boolean = false): Pair<List<X509Certificate>, List<X509Certificate>> {
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val base = "duckdetector_compare_${System.nanoTime()}"
        val challenge = ByteArray(24).also { SecureRandom().nextBytes(it) }
        return runCatching {
            val rsa = AndroidKeyStoreTools.generateAttestedRsaChain(
                keyStore,
                "${base}_rsa",
                challenge,
                useStrongBox
            )
            val ec = AndroidKeyStoreTools.generateAttestedEcChain(
                keyStore,
                "${base}_ec",
                challenge,
                useStrongBox
            )
            rsa to ec
        }.getOrDefault(emptyList<X509Certificate>() to emptyList()).also {
            AndroidKeyStoreTools.cleanup(keyStore, listOf("${base}_rsa", "${base}_ec"))
        }
    }
}
