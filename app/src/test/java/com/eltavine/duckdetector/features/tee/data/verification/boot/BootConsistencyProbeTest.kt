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

package com.eltavine.duckdetector.features.tee.data.verification.boot

import com.eltavine.duckdetector.features.tee.data.attestation.AttestationSnapshot
import com.eltavine.duckdetector.features.tee.data.attestation.AttestedApplicationInfo
import com.eltavine.duckdetector.features.tee.data.attestation.AttestedAuthState
import com.eltavine.duckdetector.features.tee.data.attestation.AttestedDeviceInfo
import com.eltavine.duckdetector.features.tee.data.attestation.AttestedKeyProperties
import com.eltavine.duckdetector.features.tee.data.attestation.RootOfTrustSnapshot
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BootConsistencyProbeTest {

    @Test
    fun `normalizes attested and runtime hex before comparing`() {
        val probe = BootConsistencyProbe(
            propertyReader = SystemPropertyReader {
                PropertyReadResult(available = true, value = "AA:BB CC")
            },
        )

        val result = probe.inspect(snapshot(rootOfTrust = rootOfTrust(hash = "aabbcc")))

        assertFalse(result.vbmetaDigestMismatch)
        assertTrue(result.detail.contains("matched", ignoreCase = true))
    }

    @Test
    fun `attested hash with empty runtime digest becomes anomaly`() {
        val probe = BootConsistencyProbe(
            propertyReader = SystemPropertyReader {
                PropertyReadResult(available = true, value = "")
            },
        )

        val result = probe.inspect(snapshot(rootOfTrust = rootOfTrust(hash = "aabb")))

        assertTrue(result.vbmetaDigestMissingWhileAttestedHashPresent)
    }

    @Test
    fun `missing root of trust stays unavailable`() {
        val probe = BootConsistencyProbe(
            propertyReader = SystemPropertyReader {
                PropertyReadResult(available = true, value = "aabb")
            },
        )

        val result = probe.inspect(snapshot(rootOfTrust = null))

        assertFalse(result.hasHardAnomaly)
        assertTrue(result.detail.contains("missing", ignoreCase = true))
    }

    @Test
    fun `verified plus unlocked stays non-anomalous for approved test-device semantics`() {
        val probe = BootConsistencyProbe(
            propertyReader = SystemPropertyReader {
                PropertyReadResult(available = true, value = "aabb")
            },
        )

        val result = probe.inspect(
            snapshot(
                rootOfTrust = RootOfTrustSnapshot(
                    verifiedBootKeyHex = "11",
                    deviceLocked = false,
                    verifiedBootState = "Verified",
                    verifiedBootHashHex = "aabb",
                ),
            ),
        )

        assertFalse(result.verifiedStateUnlockedMismatch)
        assertFalse(result.hasHardAnomaly)
        assertTrue(result.detail.contains("approved test devices", ignoreCase = true))
    }

    @Test
    fun `verified state still treats zero key and hash as anomalies`() {
        val probe = BootConsistencyProbe(
            propertyReader = SystemPropertyReader {
                PropertyReadResult(available = true, value = "00")
            },
        )

        val result = probe.inspect(
            snapshot(
                rootOfTrust = RootOfTrustSnapshot(
                    verifiedBootKeyHex = "00:00",
                    deviceLocked = true,
                    verifiedBootState = "Verified",
                    verifiedBootHashHex = "0000",
                ),
            ),
        )

        assertTrue(result.verifiedBootKeyAllZeros)
        assertTrue(result.verifiedBootHashAllZeros)
    }

    @Test
    fun `unverified state allows all-zero verified boot key and skips runtime compare`() {
        val probe = BootConsistencyProbe(
            propertyReader = SystemPropertyReader {
                PropertyReadResult(available = true, value = "aabb")
            },
        )

        val result = probe.inspect(
            snapshot(
                rootOfTrust = RootOfTrustSnapshot(
                    verifiedBootKeyHex = "00:00",
                    deviceLocked = false,
                    verifiedBootState = "Unverified",
                    verifiedBootHashHex = "aabb",
                ),
            ),
        )

        assertFalse(result.verifiedBootKeyAllZeros)
        assertFalse(result.vbmetaDigestMismatch)
        assertFalse(result.runtimeComparisonPerformed)
        assertFalse(result.hasHardAnomaly)
        assertTrue(result.detail.contains("all-zero verifiedBootKey", ignoreCase = true))
    }

    @Test
    fun `failed state skips root-of-trust anomaly claims`() {
        val probe = BootConsistencyProbe(
            propertyReader = SystemPropertyReader {
                PropertyReadResult(available = true, value = "ffff")
            },
        )

        val result = probe.inspect(
            snapshot(
                rootOfTrust = RootOfTrustSnapshot(
                    verifiedBootKeyHex = "00:00",
                    deviceLocked = true,
                    verifiedBootState = "Failed",
                    verifiedBootHashHex = "0000",
                ),
            ),
        )

        assertFalse(result.verifiedBootKeyAllZeros)
        assertFalse(result.verifiedBootHashAllZeros)
        assertFalse(result.vbmetaDigestMismatch)
        assertFalse(result.hasHardAnomaly)
        assertTrue(result.detail.contains("does not guarantee", ignoreCase = true))
    }

    private fun rootOfTrust(hash: String): RootOfTrustSnapshot {
        return RootOfTrustSnapshot(
            verifiedBootKeyHex = "112233",
            deviceLocked = true,
            verifiedBootState = "Verified",
            verifiedBootHashHex = hash,
        )
    }

    private fun snapshot(rootOfTrust: RootOfTrustSnapshot?): AttestationSnapshot {
        return AttestationSnapshot(
            tier = TeeTier.TEE,
            attestationVersion = 4,
            keymasterVersion = 4,
            attestationTier = TeeTier.TEE,
            keymasterTier = TeeTier.TEE,
            challengeVerified = true,
            challengeSummary = "len=32",
            rootOfTrust = rootOfTrust,
            osVersion = "14.0.0",
            osPatchLevel = "2026-03",
            vendorPatchLevel = null,
            bootPatchLevel = null,
            keyProperties = AttestedKeyProperties(),
            authState = AttestedAuthState(),
            applicationInfo = AttestedApplicationInfo(),
            deviceInfo = AttestedDeviceInfo(),
            deviceUniqueAttestation = false,
            trustedAttestationIndex = 0,
            rawCertificates = emptyList(),
            displayCertificates = emptyList(),
        )
    }
}
