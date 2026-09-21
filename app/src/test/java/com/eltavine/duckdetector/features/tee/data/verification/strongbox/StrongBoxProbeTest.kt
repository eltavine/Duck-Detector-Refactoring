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

package com.eltavine.duckdetector.features.tee.data.verification.strongbox

import android.security.keystore.StrongBoxUnavailableException
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import java.security.InvalidAlgorithmParameterException
import java.security.ProviderException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class StrongBoxProbeTest {

    @Test
    fun `a created key is an acceptance`() {
        assertEquals(StrongBoxAcceptance.ACCEPTED, classifyStrongBoxAcceptance(null))
        assertTrue(StrongBoxAcceptance.ACCEPTED.isDeviceObservation)
    }

    @Test
    fun `the framework parameter check is not an answer from this device`() {
        // checkValidKeySize rejects a StrongBox EC size other than 256 before Keystore is called, so
        // a secp521r1 request never becomes a question for KeyMint.
        val acceptance = classifyStrongBoxAcceptance(
            InvalidAlgorithmParameterException("Unsupported StrongBox EC key size: 521 bits."),
        )

        assertEquals(StrongBoxAcceptance.REFUSED_BY_FRAMEWORK, acceptance)
        assertFalse(acceptance.isDeviceObservation)
    }

    @Test
    fun `a keystore refusal is an answer from this device`() {
        // generateKeyPair reports every KeyMint error other than HARDWARE_TYPE_UNAVAILABLE as a plain
        // ProviderException, UNSUPPORTED_KEY_SIZE among them.
        val acceptance = classifyStrongBoxAcceptance(ProviderException("Failed to generate key pair."))

        assertEquals(StrongBoxAcceptance.REFUSED_BY_KEYSTORE, acceptance)
        assertTrue(acceptance.isDeviceObservation)
    }

    @Test
    fun `strongbox reporting itself unavailable is a keystore answer`() {
        // StrongBoxUnavailableException extends ProviderException and carries
        // KM_ERROR_HARDWARE_TYPE_UNAVAILABLE, so it belongs with the Keystore refusals.
        assertEquals(
            StrongBoxAcceptance.REFUSED_BY_KEYSTORE,
            classifyStrongBoxAcceptance(StrongBoxUnavailableException("no strongbox")),
        )
    }

    @Test
    fun `an unrelated failure leaves the question unanswered`() {
        val acceptance = classifyStrongBoxAcceptance(IllegalStateException("keystore not loaded"))

        assertEquals(StrongBoxAcceptance.INCONCLUSIVE, acceptance)
        assertFalse(acceptance.isDeviceObservation)
    }

    @Test
    fun `granting every attempted handle reports no ceiling was reached`() {
        val observation = describeConcurrentSigningHandles(
            granted = 24,
            ceiling = 24,
            failureDescription = null,
        )

        assertEquals(24, observation.granted)
        assertEquals(ConcurrentHandleStop.PROBE_CEILING, observation.stop)
        assertEquals(
            "All 24 attempted handles were granted; no ceiling was reached.",
            observation.detail,
        )
    }

    @Test
    fun `a refusal keeps the handles already granted instead of collapsing to zero`() {
        val observation = describeConcurrentSigningHandles(
            granted = 15,
            ceiling = 24,
            failureDescription = "KeyStoreException(code -68): Too many operations",
        )

        assertEquals(15, observation.granted)
        assertEquals(ConcurrentHandleStop.REFUSED, observation.stop)
        assertEquals(
            "Refused after 15 handles: KeyStoreException(code -68): Too many operations",
            observation.detail,
        )
    }

    @Test
    fun `a refusal on the first handle stays distinct from a probe that never ran`() {
        val refused = describeConcurrentSigningHandles(
            granted = 0,
            ceiling = 24,
            failureDescription = "ProviderException: Keystore operation failed",
        )

        assertEquals(ConcurrentHandleStop.REFUSED, refused.stop)
        assertEquals(ConcurrentHandleStop.SETUP_FAILED, ConcurrentSigningHandleObservation().stop)
        assertEquals(0, refused.granted)
    }

    @Test
    fun `unknown strongbox attestation tier is downgraded to warning`() {
        val assessment = assessStrongBoxAttestation(
            available = true,
            attestationTier = TeeTier.UNKNOWN,
        )

        assertNull(assessment.hardFailure)
        assertEquals(
            "StrongBox key generation succeeded, but dedicated attestation did not expose a tier.",
            assessment.warning,
        )
    }

    @Test
    fun `non strongbox attestation tier still counts as hard failure`() {
        val assessment = assessStrongBoxAttestation(
            available = true,
            attestationTier = TeeTier.TEE,
        )

        assertEquals(
            "StrongBox key generation succeeded, but attestation tier came back as TEE.",
            assessment.hardFailure,
        )
        assertNull(assessment.warning)
    }

    @Test
    fun `attestation claiming strongbox without keyinfo confirmation stays a hard failure`() {
        val assessment = assessStrongBoxAttestation(
            available = false,
            attestationTier = TeeTier.STRONGBOX,
        )

        assertEquals(
            "Attestation claimed StrongBox, but local KeyInfo could not confirm a StrongBox key.",
            assessment.hardFailure,
        )
        assertNull(assessment.warning)
    }
}
