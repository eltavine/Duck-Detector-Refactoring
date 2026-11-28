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

import android.security.keystore.StrongBoxUnavailableException
import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import java.security.KeyStore
import java.security.ProviderException

/** Why [observeConcurrentSigningHandles] stopped where it did. */
enum class ConcurrentHandleStop {
    /**
     * Every handle the probe asked for was granted, so the platform's ceiling is at or above
     * [ConcurrentSigningHandleObservation.granted] and was not reached.
     */
    PROBE_CEILING,

    /** The platform refused to begin another operation, so the observed count is a ceiling. */
    REFUSED,

    /** The key was generated but could not be read back, so no handle was ever attempted. */
    KEY_UNAVAILABLE,

    /** Key generation or KeyStore access failed, leaving the question unanswered. */
    SETUP_FAILED,
}

/**
 * How many StrongBox signing operations this app held at once, and why counting stopped.
 *
 * This is reported as an observation and never scored as an anomaly, because the number is not a
 * property of StrongBox:
 *
 * - `IKeyMintDevice` requires implementations to "support 32 concurrent operations", and the
 *   Keystore implementer reference documents at least 16 with one reserved for `vold`. Both are
 *   floors, so exceeding them is compliant behaviour rather than a deviation.
 * - When KeyMint answers `TOO_MANY_OPERATIONS`, keystore2 does not fail the caller. `operation.rs`
 *   prunes an existing operation and retries, and its candidate search ends in
 *   `candidate.or(oldest_caller_op)` — this app's own earlier handles are eligible. The framework
 *   opts app operations into that: pre-keystore2 `AndroidKeyStoreSignatureSpiBase` passes `true`
 *   for `begin`'s pruneable flag, commented "permit aborting this operation if keystore runs out of
 *   resources".
 * - Pruning is scored on inactivity age and sibling count rather than a fixed cap, and operations
 *   held by other processes compete for the same slots, so the reachable number is not stable
 *   between runs on one device.
 *
 * The count therefore describes KeyMint slots, the `km_compat` slot manager, and keystore2's
 * pruning policy jointly, and no single one of those can be attributed from it.
 */
data class ConcurrentSigningHandleObservation(
    val granted: Int = 0,
    val stop: ConcurrentHandleStop = ConcurrentHandleStop.SETUP_FAILED,
    val detail: String = "",
)

/**
 * What an attempt to generate a StrongBox key with atypical parameters established about this device.
 *
 * `AndroidKeyStoreKeyPairGeneratorSpi.initialize` in frameworks/base resolves the key size first -
 * `initAlgorithmSpecificParameters()` turns an EC curve name into its size - and only then calls
 * `checkValidKeySize`, which runs before any request reaches Keystore. A parameter set that method
 * refuses is never put to KeyMint, so the key not being created says nothing about this device's
 * StrongBox. The two refusals arrive as different exceptions, and that is what separates them here.
 *
 * The `android.security.keystore` path used before Android 12 and the `keystore2` path used from
 * Android 12 carry the same ordering and the same checks, so this holds across the supported range
 * from API 29 upwards.
 */
enum class StrongBoxAcceptance {

    /** StrongBox created a key with the requested parameters. */
    ACCEPTED,

    /**
     * Keystore or KeyMint refused, which is an observation about this device. `generateKeyPair` maps
     * `KM_ERROR_HARDWARE_TYPE_UNAVAILABLE` to `StrongBoxUnavailableException` and every other KeyMint
     * error, `UNSUPPORTED_KEY_SIZE` among them, to a plain `ProviderException`.
     */
    REFUSED_BY_KEYSTORE,

    /**
     * `checkValidKeySize` refused the parameters inside the framework, before Keystore was reached.
     * It rejects any StrongBox EC key size other than 256, so a refusal here describes the framework
     * rather than this device.
     */
    REFUSED_BY_FRAMEWORK,

    /** The attempt failed for a reason that leaves the question unanswered. */
    INCONCLUSIVE,

    ;

    /** Only [ACCEPTED] and [REFUSED_BY_KEYSTORE] are answers this device gave. */
    val isDeviceObservation: Boolean
        get() = this == ACCEPTED || this == REFUSED_BY_KEYSTORE
}

data class StrongBoxBinderObservation(
    val queryFailed: Boolean,
    val confirmedDeclaration: Boolean,
    val summary: String,
    val detail: String,
    val missingSystemFeature: Boolean = false,
) {
    val failed: Boolean
        get() = missingSystemFeature || (queryFailed && confirmedDeclaration)
}

data class StrongBoxBehaviorResult(
    val requested: Boolean,
    val advertised: Boolean,
    val available: Boolean,
    val attestationTier: TeeTier = TeeTier.UNKNOWN,
    val keyInfoLevel: String? = null,
    val keyGenerationMillis: Int? = null,
    val signingMicros: Int? = null,
    val concurrentOps: Int = 0,
    val p521Accepted: Boolean = false,
    val hardFailures: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
    val detail: String,
    /**
     * Why [keyInfoLevel] is absent, when it is absent because the question could not be answered
     * rather than because the key came back without StrongBox backing. Empty when [keyInfoLevel] was
     * read, so a reader can tell a device with no StrongBox apart from a probe that never ran.
     */
    val keyInfoUnavailableDetail: String = "",
    /**
     * Which layer answered the RSA-4096 request. [p521Accepted] stays the plain "did StrongBox take
     * it" flag; these two say whether a refusal came from this device or from the framework's own
     * parameter check, which [StrongBoxAcceptance] explains.
     */
    val rsa4096Acceptance: StrongBoxAcceptance = StrongBoxAcceptance.INCONCLUSIVE,
    val p521Acceptance: StrongBoxAcceptance = StrongBoxAcceptance.INCONCLUSIVE,
    /**
     * [concurrentOps] stays the plain granted count; this adds why counting stopped, which is what
     * decides whether that count is a ceiling the platform imposed or just where the probe gave up.
     */
    val concurrentHandles: ConcurrentSigningHandleObservation = ConcurrentSigningHandleObservation(),
    val binderObservation: StrongBoxBinderObservation? = null,
) {
    /**
     * Only [hardFailures] count. [warnings] are informational notes such as an unusually fast
     * signature, which no authoritative source makes a deviation, and the report reducer already
     * surfaces them at INFO; letting them raise suspicion here would contradict that reading.
     */
    val suspicious: Boolean
        get() = hardFailures.isNotEmpty()
}
