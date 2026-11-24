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

package com.eltavine.duckdetector.features.tee.data.verification.strongbox

import android.security.keystore.KeyInfo
import android.security.keystore.StrongBoxUnavailableException
import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import java.security.InvalidAlgorithmParameterException
import java.security.ProviderException

/**
 * Classifies a StrongBox key generation attempt by which layer refused it, from what it threw.
 *
 * `checkValidKeySize` and the rest of `AndroidKeyStoreKeyPairGeneratorSpi.initialize` report a
 * parameter set they will not pass on as [InvalidAlgorithmParameterException], before Keystore is
 * called at all. `generateKeyPair` reports a Keystore or KeyMint refusal as a [ProviderException],
 * and `StrongBoxUnavailableException` is one of those. Anything else means the attempt broke down
 * without either layer answering, so it must not be read as a refusal.
 *
 * [failure] is null when the key was created.
 */
internal fun classifyStrongBoxAcceptance(failure: Throwable?): StrongBoxAcceptance {
    return when (failure) {
        null -> StrongBoxAcceptance.ACCEPTED
        is InvalidAlgorithmParameterException -> StrongBoxAcceptance.REFUSED_BY_FRAMEWORK
        is ProviderException -> StrongBoxAcceptance.REFUSED_BY_KEYSTORE
        else -> StrongBoxAcceptance.INCONCLUSIVE
    }
}

/**
 * Turns a finished counting loop into an observation, separating "the platform stopped granting
 * handles" from "the probe ran out of attempts".
 */
internal fun describeConcurrentSigningHandles(
    granted: Int,
    ceiling: Int,
    failureDescription: String?,
): ConcurrentSigningHandleObservation {
    if (failureDescription == null) {
        return ConcurrentSigningHandleObservation(
            granted = granted,
            stop = ConcurrentHandleStop.PROBE_CEILING,
            detail = "All $ceiling attempted handles were granted; no ceiling was reached.",
        )
    }
    // The refusal is recorded, not classified further. keystore2 reports an exhausted and unprunable
    // operation database as BACKEND_BUSY while KeyMint reports TOO_MANY_OPERATIONS, and how each
    // surfaces through the JCA layer has not been verified per Android version, so naming a cause
    // here would exceed what this probe establishes.
    return ConcurrentSigningHandleObservation(
        granted = granted,
        stop = ConcurrentHandleStop.REFUSED,
        detail = "Refused after $granted handles: $failureDescription",
    )
}

internal fun assessStrongBoxAttestation(
    available: Boolean,
    attestationTier: TeeTier,
): StrongBoxAttestationAssessment {
    return when {
        available && attestationTier == TeeTier.UNKNOWN -> StrongBoxAttestationAssessment(
            warning = "StrongBox key generation succeeded, but dedicated attestation did not expose a tier.",
        )

        available && attestationTier != TeeTier.STRONGBOX -> StrongBoxAttestationAssessment(
            hardFailure = "StrongBox key generation succeeded, but attestation tier came back as $attestationTier.",
        )

        !available && attestationTier == TeeTier.STRONGBOX -> StrongBoxAttestationAssessment(
            hardFailure = "Attestation claimed StrongBox, but local KeyInfo could not confirm a StrongBox key.",
        )

        else -> StrongBoxAttestationAssessment()
    }
}

internal data class StrongBoxAttestationAssessment(
    val hardFailure: String? = null,
    val warning: String? = null,
)

internal fun assessStrongBoxIntermediateSubject(
    chain: List<X509Certificate>,
): StrongBoxAttestationAssessment {
    if (chain.isEmpty()) {
        return StrongBoxAttestationAssessment(
            warning = "StrongBox attestation certificate chain was unavailable, so its intermediate subject could not be checked.",
        )
    }

    val intermediateSubjects = chain.drop(1).dropLast(1).map {
        it.subjectX500Principal.encoded
    }
    return if (hasStrongBoxIntermediateSubjectMarker(intermediateSubjects)) {
        StrongBoxAttestationAssessment()
    } else {
        StrongBoxAttestationAssessment(
            hardFailure = "StrongBox attestation chain had no intermediate certificate subject with O=StrongBox.",
        )
    }
}

internal fun hasStrongBoxIntermediateSubjectMarker(subjects: List<ByteArray>): Boolean =
    subjects.any { encodedSubject ->
        runCatching {
            X500Name.getInstance(encodedSubject).getRDNs(BCStyle.O).any { organization ->
                organization.first.value.toString().equals("STRONGBOX", ignoreCase = true)
            }
        }.getOrDefault(false)
    }
