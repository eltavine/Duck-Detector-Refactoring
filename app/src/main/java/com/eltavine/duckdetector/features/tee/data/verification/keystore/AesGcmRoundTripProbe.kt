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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.security.KeyStore
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

class AesGcmRoundTripProbe {

    fun inspect(
        keyStore: KeyStore = AndroidKeyStoreTools.loadKeyStore(),
        useStrongBox: Boolean = false,
    ): AesGcmRoundTripResult {
        val alias = "duck_aes_gcm_${System.nanoTime()}"
        return runCatching {
            generateGcmKey(alias, useStrongBox, randomizedEncryptionRequired = true)

            val secretKey = keyStore.getKey(alias, null) as? SecretKey
                ?: return AesGcmRoundTripResult(
                    executed = true,
                    detail = "Secret key was missing after AndroidKeyStore generation.",
                )

            val secretKeyFactory =
                SecretKeyFactory.getInstance(secretKey.algorithm, "AndroidKeyStore")
            val keyInfo = secretKeyFactory.getKeySpec(secretKey, KeyInfo::class.java) as? KeyInfo
                ?: return AesGcmRoundTripResult(
                    executed = true,
                    detail = "AndroidKeyStore did not return KeyInfo for the generated AES key.",
                )
            val hardwareBacked = keyInfo.isInsideSecureHardwareCompat()
            val keyInfoLevel = keyInfoSecurityLevelLabel(
                sdkInt = Build.VERSION.SDK_INT,
                securityLevel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    keyInfo.securityLevel
                } else {
                    null
                },
                insideSecureHardware = hardwareBacked,
            )

            val plaintext = "duck_aes_gcm_probe".encodeToByteArray()
            val encryptCipher = Cipher.getInstance(CIPHER_AES_GCM)
            val encryptStart = System.nanoTime()
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey)
            val ciphertext = encryptCipher.doFinal(plaintext)
            val encryptMicros = ((System.nanoTime() - encryptStart) / 1_000L).toInt()

            val iv = encryptCipher.iv ?: byteArrayOf()
            val decryptCipher = Cipher.getInstance(CIPHER_AES_GCM)
            val decryptStart = System.nanoTime()
            decryptCipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
                GCMParameterSpec(128, iv),
            )
            val decrypted = decryptCipher.doFinal(ciphertext)
            val decryptMicros = ((System.nanoTime() - decryptStart) / 1_000L).toInt()
            val roundTripSucceeded = plaintext.contentEquals(decrypted)
            val auth = gcmAuthorizationChecks(useStrongBox)

            AesGcmRoundTripResult(
                executed = true,
                roundTripSucceeded = roundTripSucceeded,
                cbcRejected = auth.cbcRejected.ok,
                cbcRejectedDetail = auth.cbcRejected.detail,
                mac64Rejected = auth.mac64Rejected.ok,
                mac64RejectedDetail = auth.mac64Rejected.detail,
                shortNonceRejected = auth.shortNonceRejected.ok,
                shortNonceRejectedDetail = auth.shortNonceRejected.detail,
                keyInfoLevel = keyInfoLevel,
                insideSecureHardware = hardwareBacked,
                cipherProvider = encryptCipher.provider?.name,
                encryptMicros = encryptMicros,
                decryptMicros = decryptMicros,
                detail = buildString {
                    append("keyInfo=")
                    append(keyInfoLevel)
                    append(", insideSecureHardware=")
                    append(hardwareBacked)
                    append(", encryptUs=")
                    append(encryptMicros)
                    append(", decryptUs=")
                    append(decryptMicros)
                    encryptCipher.provider?.name?.let {
                        append(", provider=")
                        append(it)
                    }
                    append(", roundTrip=")
                    append(if (roundTripSucceeded) "ok" else "failed")
                    append(", auth=")
                    append(if (auth.ok) "ok" else "failed")
                },
            )
        }.getOrElse { throwable ->
            AesGcmRoundTripResult(
                executed = true,
                detail = throwable.message ?: "AES-GCM keystore round-trip probe failed.",
            )
        }.also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }

    private fun gcmAuthorizationChecks(useStrongBox: Boolean): AesGcmAuthorizationChecks {
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duck_aes_gcm_auth_${System.nanoTime()}"
        return try {
            val key = generateGcmKey(alias, useStrongBox, randomizedEncryptionRequired = false)
            AesGcmAuthorizationChecks(
                cbcRejected = rejectEncrypt(key, "AES/CBC/PKCS7Padding"),
                mac64Rejected = rejectEncrypt(
                    key,
                    CIPHER_AES_GCM,
                    GCMParameterSpec(64, ByteArray(12) { it.toByte() }),
                ),
                shortNonceRejected = rejectEncrypt(
                    key,
                    CIPHER_AES_GCM,
                    GCMParameterSpec(128, ByteArray(8) { it.toByte() }),
                ),
            )
        } catch (throwable: Throwable) {
            val skipped = CheckResult(true, throwable.message ?: "AES-GCM authorization checks unavailable.")
            AesGcmAuthorizationChecks(skipped, skipped, skipped)
        } finally {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }

    private fun generateGcmKey(
        alias: String,
        useStrongBox: Boolean,
        randomizedEncryptionRequired: Boolean,
    ): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(128)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(randomizedEncryptionRequired)
        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        generator.init(builder.build())
        return generator.generateKey()
    }

    private fun rejectEncrypt(
        key: SecretKey,
        transform: String,
        params: AlgorithmParameterSpec? = null,
    ): CheckResult {
        val succeeded = runCatching {
            Cipher.getInstance(transform).apply {
                if (params == null) init(Cipher.ENCRYPT_MODE, key) else init(Cipher.ENCRYPT_MODE, key, params)
            }.doFinal("duck_aes_gcm_auth".encodeToByteArray())
        }.isSuccess
        return CheckResult(!succeeded, "unauthorizedEncryptSucceeded=$succeeded")
    }
}

data class AesGcmRoundTripResult(
    val executed: Boolean,
    val roundTripSucceeded: Boolean = false,
    val cbcRejected: Boolean = true,
    val cbcRejectedDetail: String = "AES-GCM CBC authorization skipped.",
    val mac64Rejected: Boolean = true,
    val mac64RejectedDetail: String = "AES-GCM MAC length authorization skipped.",
    val shortNonceRejected: Boolean = true,
    val shortNonceRejectedDetail: String = "AES-GCM nonce authorization skipped.",
    val keyInfoLevel: String? = null,
    val insideSecureHardware: Boolean? = null,
    val cipherProvider: String? = null,
    val encryptMicros: Int? = null,
    val decryptMicros: Int? = null,
    val detail: String,
)

private data class AesGcmAuthorizationChecks(
    val cbcRejected: CheckResult,
    val mac64Rejected: CheckResult,
    val shortNonceRejected: CheckResult,
) {
    val ok: Boolean = cbcRejected.ok && mac64Rejected.ok && shortNonceRejected.ok
}

private data class CheckResult(
    val ok: Boolean,
    val detail: String,
)

private const val CIPHER_AES_GCM = "AES/GCM/NoPadding"

@Suppress("DEPRECATION")
internal fun KeyInfo.isInsideSecureHardwareCompat(): Boolean = isInsideSecureHardware

@Suppress("DEPRECATION")
internal fun keyInfoSecurityLevelLabel(
    sdkInt: Int,
    securityLevel: Int?,
    insideSecureHardware: Boolean,
): String {
    return if (sdkInt >= Build.VERSION_CODES.S && securityLevel != null) {
        when (securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> "Software"
            else -> if (insideSecureHardware) "SecureHardware" else "Software"
        }
    } else if (insideSecureHardware) {
        "SecureHardware"
    } else {
        "Software"
    }
}
