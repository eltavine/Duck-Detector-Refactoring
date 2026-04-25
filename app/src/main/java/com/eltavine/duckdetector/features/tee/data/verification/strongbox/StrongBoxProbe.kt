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

        if (testRsa4096Acceptance()) {
            warnings += "StrongBox accepted RSA-4096, which is atypical for current hardware-backed implementations."
        }
        val p521Accepted = testP521Support()
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
            p521Accepted = p521Accepted,
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
                append(", p521=")
                append(if (p521Accepted) "accepted" else "rejected")
            },
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
            val key = keyStore.getKey(alias, null) ?: return KeyInfoResult()
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
        }.recover {
            if (it is StrongBoxUnavailableException) {
                KeyInfoResult()
            } else {
                KeyInfoResult()
            }
        }.getOrDefault(KeyInfoResult()).also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }

    private fun testRsa4096Acceptance(): Boolean {
        val alias = "duck_sb_rsa_${System.nanoTime()}"
        return runCatching {
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
            true
        }.getOrDefault(false)
    }

    private fun testP521Support(): Boolean {
        val alias = "duck_sb_p521_${System.nanoTime()}"
        return runCatching {
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
            true
        }.getOrDefault(false)
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

    private data class KeyInfoResult(
        val keyInfoLevel: String? = null,
        val keyGenerationMillis: Int? = null,
    )

    private fun expectedConcurrentSigningHandleLimit(): Int {
        return expectedConcurrentSigningHandleLimit(
            brand = Build.BRAND,
            manufacturer = Build.MANUFACTURER,
            model = Build.MODEL,
        )
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
) {
    val suspicious: Boolean
        get() = hardFailures.isNotEmpty() || warnings.isNotEmpty()
}
