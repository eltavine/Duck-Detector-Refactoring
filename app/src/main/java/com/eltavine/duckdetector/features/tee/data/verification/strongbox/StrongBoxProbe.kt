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

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.eltavine.duckdetector.features.tee.data.attestation.AndroidAttestationCollector
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import com.eltavine.duckdetector.features.tee.data.verification.keystore.isInsideSecureHardwareCompat
import com.eltavine.duckdetector.features.tee.data.verification.keystore.keyInfoSecurityLevelLabel
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.InvalidAlgorithmParameterException
import java.security.ProviderException
import java.security.spec.ECGenParameterSpec

class StrongBoxBehaviorProbeSuite(
    context: Context,
    private val collector: AndroidAttestationCollector = AndroidAttestationCollector(),
) {

    private val appContext = context.applicationContext

    fun inspect(): StrongBoxBehaviorResult {
        val advertised =
            appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (!advertised) {
            return StrongBoxBehaviorResult(
                requested = false,
                advertised = false,
                available = false,
                detail = "The device does not advertise StrongBox support.",
            )
        }

        val hardFailures = mutableListOf<String>()
        val warnings = mutableListOf<String>()
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val keyInfoResult = generateStrongBoxKeyInfo(keyStore)
        val available = keyInfoResult.keyInfoLevel == "StrongBox"
        val attestation = runCatching { collector.collect(useStrongBox = true) }.getOrNull()
        val attestationTier = attestation?.tier ?: TeeTier.UNKNOWN
        val attestationAssessment = assessStrongBoxAttestation(available, attestationTier)

        attestationAssessment.hardFailure?.let(hardFailures::add)
        attestationAssessment.warning?.let(warnings::add)

        val rsa4096Acceptance = testRsa4096Acceptance()
        if (rsa4096Acceptance == StrongBoxAcceptance.ACCEPTED) {
            warnings += "StrongBox accepted RSA-4096, which is atypical for current hardware-backed implementations."
        }
        val p521Acceptance = testP521Support()
        // These two thresholds are tripwires, not spec violations. CDD 9.11 states no latency or
        // throughput target for StrongBox: C-1-3 through C-1-11 require a discrete CPU, a clock
        // accurate to +-10%, a TRNG and tamper resistance, and C-1-8 requires resistance to timing
        // side channels, so timing is a hardened property rather than a specified one. The Keystore
        // documentation only says StrongBox "is slower, more resource-constrained, and supports
        // fewer concurrent operations", which is qualitative. Both notes therefore stay
        // informational and carry the measurement so a reader can judge it.
        val signingMicros = measureSigningMicros(keyStore)
        if (signingMicros != null && signingMicros < SIGNING_TRIPWIRE_MICROS) {
            warnings += "StrongBox signing returned in ${signingMicros}us, under the ${SIGNING_TRIPWIRE_MICROS}us this probe expects of a discrete secure element."
        }
        val keygenMillis = keyInfoResult.keyGenerationMillis
        if (keygenMillis != null && keygenMillis < KEYGEN_TRIPWIRE_MILLIS) {
            warnings += "StrongBox key generation completed in ${keygenMillis}ms, under the ${KEYGEN_TRIPWIRE_MILLIS}ms this probe expects of a discrete secure element."
        }
        // Recorded, not scored: see ConcurrentSigningHandleObservation for why the number of
        // handles this app can hold is not a property of StrongBox.
        val concurrentHandles = observeConcurrentSigningHandles(keyStore)

        return StrongBoxBehaviorResult(
            requested = true,
            advertised = true,
            available = available,
            attestationTier = attestationTier,
            keyInfoLevel = keyInfoResult.keyInfoLevel,
            keyGenerationMillis = keygenMillis,
            signingMicros = signingMicros,
            concurrentOps = concurrentHandles.granted,
            p521Accepted = p521Acceptance == StrongBoxAcceptance.ACCEPTED,
            hardFailures = hardFailures,
            warnings = warnings,
            detail = buildString {
                append("advertised=")
                append(advertised)
                append(", available=")
                append(available)
                append(", keyInfo=")
                append(keyInfoResult.keyInfoLevel ?: "unknown")
                append(", attestation=")
                append(attestationTier)
                keygenMillis?.let {
                    append(", keygenMs=")
                    append(it)
                }
                signingMicros?.let {
                    append(", signUs=")
                    append(it)
                }
                append(", concurrentHandles=")
                append(concurrentHandles.granted)
                append(", concurrentStop=")
                append(concurrentHandles.stop)
                if (concurrentHandles.detail.isNotBlank()) {
                    append(", concurrentDetail=")
                    append(concurrentHandles.detail)
                }
                // Naming the layer that refused keeps a framework-side parameter check from reading
                // as an answer this device gave.
                append(", p521=")
                append(p521Acceptance)
                append(", rsa4096=")
                append(rsa4096Acceptance)
                if (keyInfoResult.unavailableDetail.isNotBlank()) {
                    append(", keyInfoUnavailable=")
                    append(keyInfoResult.unavailableDetail)
                }
            },
            keyInfoUnavailableDetail = keyInfoResult.unavailableDetail,
            rsa4096Acceptance = rsa4096Acceptance,
            p521Acceptance = p521Acceptance,
            concurrentHandles = concurrentHandles,
        )
    }

    private fun generateStrongBoxKeyInfo(keyStore: KeyStore): KeyInfoResult {
        val alias = "duck_sb_info_${System.nanoTime()}"
        return runCatching {
            val generator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val start = System.nanoTime()
            val builder = android.security.keystore.KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN,
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setIsStrongBoxBacked(true)
            generator.initialize(builder.build())
            generator.generateKeyPair()
            // A non-local return here would have skipped the safeDelete in the also block below and
            // left the generated key in the store.
            val key = keyStore.getKey(alias, null) ?: return@runCatching KeyInfoResult(
                unavailableDetail = "StrongBox key generation succeeded but the key was absent from the store.",
            )
            val keyFactory = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            val keyInfo = keyFactory.getKeySpec(key, KeyInfo::class.java)
            val level = keyInfoSecurityLevelLabel(
                sdkInt = Build.VERSION.SDK_INT,
                securityLevel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    keyInfo.securityLevel
                } else {
                    null
                },
                insideSecureHardware = keyInfo.isInsideSecureHardwareCompat(),
            )
            KeyInfoResult(
                keyInfoLevel = level,
                keyGenerationMillis = ((System.nanoTime() - start) / 1_000_000L).toInt(),
            )
        }.getOrElse { failure ->
            // Both branches of the previous recover returned the same empty result, so a device with
            // no StrongBox and a key generation that never reached StrongBox produced an identical
            // KeyInfoResult. available is derived from keyInfoLevel and feeds a hard failure, so the
            // two have to stay apart: StrongBoxUnavailableException is the documented answer that no
            // StrongBox exists, while anything else leaves the question unanswered.
            KeyInfoResult(
                unavailableDetail = if (failure is StrongBoxUnavailableException) {
                    "StrongBox reported itself unavailable during key generation."
                } else {
                    "StrongBox key generation did not complete: ${describeFailure(failure)}"
                },
            )
        }.also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }

    private fun classifyAcceptance(attempt: () -> Unit): StrongBoxAcceptance =
        classifyStrongBoxAcceptance(runCatching(attempt).exceptionOrNull())

    /**
     * Asks StrongBox for an RSA-4096 key.
     *
     * `checkValidKeySize` only bounds RSA between `RSA_MIN_KEY_SIZE` and `RSA_MAX_KEY_SIZE`, which is
     * 8192, and applies no StrongBox-specific limit, so this request does reach KeyMint and the
     * answer describes this device. The Keystore documentation lists RSA-2048 as the StrongBox size,
     * so acceptance here is worth reporting.
     */
    private fun testRsa4096Acceptance(): StrongBoxAcceptance = classifyAcceptance {
        val alias = "duck_sb_rsa_${System.nanoTime()}"
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val generator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
        val builder = android.security.keystore.KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setKeySize(4096)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setIsStrongBoxBacked(true)
        generator.initialize(builder.build())
        generator.generateKeyPair()
        AndroidKeyStoreTools.safeDelete(keyStore, alias)
    }

    /**
     * Asks StrongBox for a secp521r1 key.
     *
     * `initAlgorithmSpecificParameters()` resolves the curve name to 521 bits before
     * `checkValidKeySize` runs, and that method rejects any StrongBox EC size other than 256. The
     * request therefore never reaches KeyMint on a stock framework and the expected outcome is
     * [StrongBoxAcceptance.REFUSED_BY_FRAMEWORK], which is not an observation about this device. A
     * [StrongBoxAcceptance.REFUSED_BY_KEYSTORE] or [StrongBoxAcceptance.ACCEPTED] answer would mean
     * the framework check did not behave as the AOSP sources describe.
     */
    private fun testP521Support(): StrongBoxAcceptance = classifyAcceptance {
        val alias = "duck_sb_p521_${System.nanoTime()}"
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val generator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val builder = android.security.keystore.KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp521r1"))
            .setDigests(KeyProperties.DIGEST_SHA512)
            .setIsStrongBoxBacked(true)
        generator.initialize(builder.build())
        generator.generateKeyPair()
        AndroidKeyStoreTools.safeDelete(keyStore, alias)
    }

    private fun measureSigningMicros(keyStore: KeyStore): Int? {
        val alias = "duck_sb_sign_${System.nanoTime()}"
        return runCatching {
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = "CN=DuckDetector StrongBox Sign, O=Eltavine",
                useStrongBox = true,
            )
            // A non-local return here would skip the safeDelete in the also block below and leave
            // the generated key in the store.
            val privateKey = AndroidKeyStoreTools.readPrivateKey(keyStore, alias)
                ?: return@runCatching null
            val timings = buildList {
                repeat(8) {
                    val signature = Signature.getInstance("SHA256withECDSA")
                    val start = System.nanoTime()
                    signature.initSign(privateKey)
                    signature.update("duck_sb_sign_$it".encodeToByteArray())
                    signature.sign()
                    add(((System.nanoTime() - start) / 1_000L).toInt())
                }
            }.sorted()
            timings[timings.size / 2]
        }.getOrNull().also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }

    /**
     * Holds signing operations open to see how many this app can have in flight at once.
     *
     * Every operation begun here is released in the `finally` block. `IKeyMintDevice.begin` states
     * that a caller which never pairs `begin` with `finish` or `abort` "may leak internal state
     * space or other internal resources and may eventually cause begin() to return
     * ErrorCode::TOO_MANY_OPERATIONS", so a probe that abandoned the handles it opened would
     * degrade every later KeyStore probe in this process.
     */
    private fun observeConcurrentSigningHandles(keyStore: KeyStore): ConcurrentSigningHandleObservation {
        val alias = "duck_sb_slots_${System.nanoTime()}"
        val opened = mutableListOf<Signature>()
        return try {
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = "CN=DuckDetector StrongBox Slots, O=Eltavine",
                useStrongBox = true,
            )
            val privateKey = AndroidKeyStoreTools.readPrivateKey(keyStore, alias)
                ?: return ConcurrentSigningHandleObservation(
                    stop = ConcurrentHandleStop.KEY_UNAVAILABLE,
                    detail = "The StrongBox key was generated but could not be read back for signing.",
                )
            var refusal: Throwable? = null
            for (index in 0 until CONCURRENT_HANDLE_PROBE_CEILING) {
                // AndroidKeyStoreSignatureSpiBase.engineInitSign calls
                // ensureKeystoreOperationInitialized, which begins the KeyMint operation, so the
                // handle is taken here rather than at sign().
                val signature = Signature.getInstance("SHA256withECDSA")
                try {
                    signature.initSign(privateKey)
                    // Recorded the moment the operation exists, so a later failure still releases it.
                    opened += signature
                    signature.update("duck_slot_$index".encodeToByteArray())
                } catch (failure: Throwable) {
                    refusal = failure
                    break
                }
            }
            describeConcurrentSigningHandles(
                granted = opened.size,
                ceiling = CONCURRENT_HANDLE_PROBE_CEILING,
                failureDescription = refusal?.let(::describeFailure),
            )
        } catch (failure: Throwable) {
            ConcurrentSigningHandleObservation(
                granted = opened.size,
                stop = ConcurrentHandleStop.SETUP_FAILED,
                detail = describeFailure(failure),
            )
        } finally {
            opened.forEach { runCatching { it.sign() } }
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }

    /**
     * Names a throwable for the exported report without claiming what it implies about StrongBox.
     */
    private fun describeFailure(failure: Throwable): String {
        val type = failure::class.java.simpleName
        val message = failure.message?.takeIf(String::isNotBlank)
        return if (message == null) type else "$type: $message"
    }

    private data class KeyInfoResult(
        val keyInfoLevel: String? = null,
        val keyGenerationMillis: Int? = null,
        val unavailableDetail: String = "",
    )

}

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
 * How many concurrent signing handles the probe attempted. The platform grants or refuses each one;
 * this only bounds the work, and a run that reaches it has not found a ceiling.
 */
private const val CONCURRENT_HANDLE_PROBE_CEILING = 24

/**
 * Signing faster than this is treated as worth noting rather than as a deviation, because no
 * authoritative source specifies StrongBox latency. The measurement spans initSign through sign, so
 * it includes the Binder round trips to keystore2 and the HAL, not secure-element compute alone.
 */
private const val SIGNING_TRIPWIRE_MICROS = 2_000

/** Key generation counterpart to [SIGNING_TRIPWIRE_MICROS], and heuristic for the same reason. */
private const val KEYGEN_TRIPWIRE_MILLIS = 20

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
) {
    /**
     * Only [hardFailures] count. [warnings] are informational notes such as an unusually fast
     * signature, which no authoritative source makes a deviation, and the report reducer already
     * surfaces them at INFO; letting them raise suspicion here would contradict that reading.
     */
    val suspicious: Boolean
        get() = hardFailures.isNotEmpty()
}
