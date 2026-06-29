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
import android.security.keystore.KeyProperties
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.Mac

class KeyMintCapabilityProbe {
    fun inspect(useStrongBox: Boolean = false): KeyMintCapabilityResult {
        val hmac = hmacSha256(useStrongBox)
        val limitedUseEc = limitedUseEc(useStrongBox)
        val ecdh = ecdhP256(useStrongBox)
        val rsaPss = rsaPssSha256(useStrongBox)
        return KeyMintCapabilityResult(
            executed = true,
            hmacSha256Ok = hmac.ok,
            hmacSha256Detail = hmac.detail,
            limitedUseEcExecuted = limitedUseEc.executed,
            limitedUseEcOk = limitedUseEc.ok,
            limitedUseEcDetail = limitedUseEc.detail,
            ecdhP256Executed = ecdh.executed,
            ecdhP256Ok = ecdh.ok,
            ecdhP256Detail = ecdh.detail,
            rsaPssSha256Ok = rsaPss.ok,
            rsaPssSha256Detail = rsaPss.detail,
        )
    }

    private fun hmacSha256(useStrongBox: Boolean): CheckResult {
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duck_keymint_hmac_${System.nanoTime()}"
        return runCatching {
            val generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_HMAC_SHA256,
                "AndroidKeyStore",
            )
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setKeySize(256)
                .setDigests(KeyProperties.DIGEST_SHA256)
            if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(true)
            }
            generator.init(builder.build())
            val key = generator.generateKey()
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(key)
            val output = mac.doFinal("duck_hmac_capability".encodeToByteArray())
            CheckResult(output.size == 32, "HMAC-SHA256 output bytes=${output.size}.")
        }.getOrElse {
            CheckResult(false, it.message ?: "HMAC-SHA256 generation failed.")
        }.also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }

    private fun limitedUseEc(useStrongBox: Boolean): CheckResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return CheckResult(
                ok = true,
                detail = "Single-use EC requires Android 12 or newer.",
                executed = false,
            )
        }
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_usage_${System.nanoTime()}"
        return runCatching {
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore",
            )
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setMaxUsageCount(1)
            if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(true)
            }
            generator.initialize(builder.build())
            generator.generateKeyPair()
            val key = keyStore.getKey(alias, null) as PrivateKey
            val firstUseOk = sign(key, "first")
            val secondUseOk = sign(key, "second")
            CheckResult(
                firstUseOk && !secondUseOk,
                "firstUse=$firstUseOk, secondUse=$secondUseOk.",
            )
        }.getOrElse {
            CheckResult(false, it.message ?: "Single-use EC generation failed.")
        }.also {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun ecdhP256(useStrongBox: Boolean): CheckResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return CheckResult(
                ok = true,
                detail = "ECDH requires Android 12 or newer.",
                executed = false,
            )
        }
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_ecdh_${System.nanoTime()}"
        return runCatching {
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore",
            )
            val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(true)
            }
            generator.initialize(builder.build())
            val keyPair = generator.generateKeyPair()

            val peer = KeyPairGenerator.getInstance("EC").apply {
                initialize(ECGenParameterSpec("secp256r1"))
            }.generateKeyPair()
            val agreement = KeyAgreement.getInstance("ECDH", "AndroidKeyStore")
            agreement.init(keyPair.private)
            agreement.doPhase(peer.public, true)
            val secret = agreement.generateSecret()
            CheckResult(secret.isNotEmpty(), "ECDH secret bytes=${secret.size}.")
        }.getOrElse {
            CheckResult(false, it.message ?: "ECDH P-256 key agreement failed.")
        }.also {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun rsaPssSha256(useStrongBox: Boolean): CheckResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_rsapss_${System.nanoTime()}"
        return runCatching {
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA,
                "AndroidKeyStore",
            )
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setKeySize(2048)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
            if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(true)
            }
            generator.initialize(builder.build())
            val keyPair = generator.generateKeyPair()
            val message = "duck_rsapss_capability".encodeToByteArray()
            val signer = Signature.getInstance("SHA256withRSA/PSS")
            signer.initSign(keyPair.private)
            signer.update(message)
            val signature = signer.sign()

            val publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(X509EncodedKeySpec(keyPair.public.encoded))
            val verifier = Signature.getInstance("SHA256withRSA/PSS")
            verifier.initVerify(publicKey)
            verifier.update(message)
            val verified = verifier.verify(signature)
            CheckResult(verified, "signature bytes=${signature.size}, verified=$verified.")
        }.getOrElse {
            CheckResult(false, it.message ?: "RSA-PSS SHA-256 signing failed.")
        }.also {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun sign(key: PrivateKey, label: String): Boolean = runCatching {
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(key)
        signer.update("duck_usage_$label".encodeToByteArray())
        signer.sign()
        true
    }.getOrDefault(false)

    private data class CheckResult(
        val ok: Boolean,
        val detail: String,
        val executed: Boolean = true,
    )
}

data class KeyMintCapabilityResult(
    val executed: Boolean,
    val hmacSha256Ok: Boolean = true,
    val hmacSha256Detail: String,
    val limitedUseEcExecuted: Boolean = true,
    val limitedUseEcOk: Boolean = true,
    val limitedUseEcDetail: String,
    val ecdhP256Executed: Boolean = true,
    val ecdhP256Ok: Boolean = true,
    val ecdhP256Detail: String = "ECDH P-256 skipped.",
    val rsaPssSha256Ok: Boolean = true,
    val rsaPssSha256Detail: String = "RSA-PSS SHA-256 skipped.",
)
