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

import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.eltavine.duckdetector.capability.attestation.data.AndroidAttestationCollector
import com.eltavine.duckdetector.capability.attestation.data.AndroidKeyStoreTools
import com.eltavine.duckdetector.core.platform.PlatformFailureName
import com.eltavine.duckdetector.features.tee.data.verification.keystore.isInsideSecureHardwareCompat
import com.eltavine.duckdetector.features.tee.data.verification.keystore.keyInfoSecurityLevelLabel
import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec

internal class StrongBoxBehaviorProbeSuite(
    private val collector: AndroidAttestationCollector = AndroidAttestationCollector(),
) {
    fun inspect(advertised: Boolean): StrongBoxBehaviorResult {
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
        val subjectAssessment = assessStrongBoxIntermediateSubject(attestation?.rawCertificates.orEmpty())
        subjectAssessment.hardFailure?.let(hardFailures::add)
        subjectAssessment.warning?.let(warnings::add)

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
    private fun describeFailure(failure: Throwable): String = PlatformFailureName.describe(failure)

    private data class KeyInfoResult(
        val keyInfoLevel: String? = null,
        val keyGenerationMillis: Int? = null,
        val unavailableDetail: String = "",
    )

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
