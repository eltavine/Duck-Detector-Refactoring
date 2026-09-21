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
    private val concurrentHandleLimit = expectedConcurrentSigningHandleLimit()

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
        val signingMicros = measureSigningMicros(keyStore)
        if (signingMicros != null && signingMicros < 2_000) {
            warnings += "StrongBox signing returned in under 2 ms."
        }
        val keygenMillis = keyInfoResult.keyGenerationMillis
        if (keygenMillis != null && keygenMillis < 20) {
            warnings += "StrongBox key generation completed in under 20 ms."
        }
        val concurrentOps = testConcurrentOps(keyStore)
        if (concurrentOps > concurrentHandleLimit) {
            warnings += "StrongBox allowed more than $concurrentHandleLimit simultaneous signing handles."
        }

        return StrongBoxBehaviorResult(
            requested = true,
            advertised = true,
            available = available,
            attestationTier = attestationTier,
            keyInfoLevel = keyInfoResult.keyInfoLevel,
            keyGenerationMillis = keygenMillis,
            signingMicros = signingMicros,
            concurrentOps = concurrentOps,
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
                append(", concurrentOps=")
                append(concurrentOps)
                append(", concurrentLimit=")
                append(concurrentHandleLimit)
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
            val privateKey = AndroidKeyStoreTools.readPrivateKey(keyStore, alias) ?: return null
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

    private fun testConcurrentOps(keyStore: KeyStore): Int {
        val alias = "duck_sb_slots_${System.nanoTime()}"
        return runCatching {
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = "CN=DuckDetector StrongBox Slots, O=Eltavine",
                useStrongBox = true,
            )
            val privateKey = AndroidKeyStoreTools.readPrivateKey(keyStore, alias) ?: return 0
            val signatures = mutableListOf<Signature>()
            var count = 0
            repeat(24) { index ->
                val signature = Signature.getInstance("SHA256withECDSA")
                signature.initSign(privateKey)
                signature.update("duck_slot_$index".encodeToByteArray())
                signatures += signature
                count += 1
            }
            signatures.forEach { runCatching { it.sign() } }
            count
        }.getOrDefault(0).also {
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

    private fun expectedConcurrentSigningHandleLimit(): Int {
        return expectedConcurrentSigningHandleLimit(
            brand = Build.BRAND,
            manufacturer = Build.MANUFACTURER,
            model = Build.MODEL,
        )
    }
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

internal fun expectedConcurrentSigningHandleLimit(
    brand: String,
    manufacturer: String,
    model: String,
): Int {
    return if (isPixelDeviceProfile(brand, manufacturer, model)) 128 else 16
}

internal fun isPixelDeviceProfile(
    brand: String,
    manufacturer: String,
    model: String,
): Boolean {
    val brandGoogle = brand.equals("google", ignoreCase = true)
    val manufacturerGoogle = manufacturer.equals("google", ignoreCase = true)
    val modelPixel = Regex("^Pixel\\b", RegexOption.IGNORE_CASE).containsMatchIn(model)
    return modelPixel && (brandGoogle || manufacturerGoogle)
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
) {
    val suspicious: Boolean
        get() = hardFailures.isNotEmpty() || warnings.isNotEmpty()
}
