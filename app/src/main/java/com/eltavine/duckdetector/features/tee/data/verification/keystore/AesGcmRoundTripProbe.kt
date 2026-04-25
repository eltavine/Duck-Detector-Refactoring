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
            val generator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(128)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
            if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(true)
            }
            generator.init(builder.build())
            generator.generateKey()

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
            val encryptCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val encryptStart = System.nanoTime()
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey)
            val ciphertext = encryptCipher.doFinal(plaintext)
            val encryptMicros = ((System.nanoTime() - encryptStart) / 1_000L).toInt()

            val iv = encryptCipher.iv ?: byteArrayOf()
            val decryptCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val decryptStart = System.nanoTime()
            decryptCipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
                GCMParameterSpec(128, iv),
            )
            val decrypted = decryptCipher.doFinal(ciphertext)
            val decryptMicros = ((System.nanoTime() - decryptStart) / 1_000L).toInt()
            val roundTripSucceeded = plaintext.contentEquals(decrypted)

            AesGcmRoundTripResult(
                executed = true,
                roundTripSucceeded = roundTripSucceeded,
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
}

data class AesGcmRoundTripResult(
    val executed: Boolean,
    val roundTripSucceeded: Boolean = false,
    val keyInfoLevel: String? = null,
    val insideSecureHardware: Boolean? = null,
    val cipherProvider: String? = null,
    val encryptMicros: Int? = null,
    val decryptMicros: Int? = null,
    val detail: String,
)

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
