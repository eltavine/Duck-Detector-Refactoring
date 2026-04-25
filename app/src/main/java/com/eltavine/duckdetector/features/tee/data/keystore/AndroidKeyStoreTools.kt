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

package com.eltavine.duckdetector.features.tee.data.keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Calendar
import javax.crypto.KeyGenerator
import javax.security.auth.x500.X500Principal

object AndroidKeyStoreTools {

    fun loadKeyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun safeDelete(keyStore: KeyStore, alias: String) {
        runCatching {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        }
    }

    fun cleanup(keyStore: KeyStore, aliases: Iterable<String>) {
        aliases.forEach { alias -> safeDelete(keyStore, alias) }
    }

    fun generateAttestedEcChain(
        keyStore: KeyStore,
        alias: String,
        challenge: ByteArray,
        useStrongBox: Boolean = false,
    ): List<X509Certificate> {
        safeDelete(keyStore, alias)
        val builder = baseBuilder(alias, challenge, useStrongBox)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore",
        )
        generator.initialize(builder.build())
        generator.generateKeyPair()
        return readCertificateChain(keyStore, alias)
    }

    fun generateAttestedRsaChain(
        keyStore: KeyStore,
        alias: String,
        challenge: ByteArray,
        useStrongBox: Boolean = false,
    ): List<X509Certificate> {
        safeDelete(keyStore, alias)
        val builder = baseBuilder(alias, challenge, useStrongBox)
            .setKeySize(2048)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            "AndroidKeyStore",
        )
        generator.initialize(builder.build())
        generator.generateKeyPair()
        return readCertificateChain(keyStore, alias)
    }

    fun generateSigningEcKey(
        keyStore: KeyStore,
        alias: String,
        subject: String,
        useStrongBox: Boolean,
        challenge: ByteArray? = null,
    ) {
        safeDelete(keyStore, alias)
        val builder = signingBuilder(alias, subject, useStrongBox)
        challenge?.let { builder.setAttestationChallenge(it) }
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore",
        )
        generator.initialize(builder.build())
        generator.generateKeyPair()
    }

    fun generateAttestOnlyEcKey(
        keyStore: KeyStore,
        alias: String,
    ): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return false
        }
        return runCatching {
            safeDelete(keyStore, alias)
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore",
            )
            val spec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ATTEST_KEY,
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setAttestationChallenge("duck_attest_${System.nanoTime()}".toByteArray())
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
            generator.initialize(spec)
            generator.generateKeyPair()
            true
        }.getOrDefault(false)
    }

    fun readCertificateChain(keyStore: KeyStore, alias: String): List<X509Certificate> {
        return keyStore.getCertificateChain(alias)
            ?.filterIsInstance<X509Certificate>()
            .orEmpty()
    }

    fun readLeafCertificate(keyStore: KeyStore, alias: String): X509Certificate? {
        return keyStore.getCertificate(alias) as? X509Certificate
    }

    fun readPrivateKey(keyStore: KeyStore, alias: String): PrivateKey? {
        return keyStore.getKey(alias, null) as? PrivateKey
    }

    fun signData(privateKey: PrivateKey, payload: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        signature.update(payload)
        return signature.sign()
    }

    fun generateBiometricBoundAesKey(
        keyStore: KeyStore,
        alias: String,
    ) {
        safeDelete(keyStore, alias)
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                30,
                KeyProperties.AUTH_BIOMETRIC_STRONG,
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(30)
        }
        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore",
        )
        generator.init(builder.build())
        generator.generateKey()
    }

    private fun baseBuilder(
        alias: String,
        challenge: ByteArray,
        useStrongBox: Boolean,
    ): KeyGenParameterSpec.Builder {
        val start = Calendar.getInstance()
        val end = Calendar.getInstance().apply { add(Calendar.YEAR, 1) }
        return KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setCertificateSubject(X500Principal("CN=DuckDetector Tee, O=Eltavine"))
            .setCertificateSerialNumber(BigInteger.valueOf(System.nanoTime()))
            .setCertificateNotBefore(start.time)
            .setCertificateNotAfter(end.time)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .apply {
                if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                }
            }
    }

    private fun signingBuilder(
        alias: String,
        subject: String,
        useStrongBox: Boolean,
    ): KeyGenParameterSpec.Builder {
        val start = Calendar.getInstance()
        val end = Calendar.getInstance().apply { add(Calendar.YEAR, 1) }
        return KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setCertificateSubject(X500Principal(subject))
            .setCertificateSerialNumber(BigInteger.valueOf(System.nanoTime()))
            .setCertificateNotBefore(start.time)
            .setCertificateNotAfter(end.time)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .apply {
                if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                }
            }
    }
}
