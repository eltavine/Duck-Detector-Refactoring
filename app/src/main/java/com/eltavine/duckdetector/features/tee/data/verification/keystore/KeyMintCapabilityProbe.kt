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
import android.os.Process
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.math.BigInteger
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Calendar
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.security.auth.x500.X500Principal

class KeyMintCapabilityProbe {
    fun inspect(attestationVersion: Int = 2, useStrongBox: Boolean = false): KeyMintCapabilityResult {
        val hmac = hmacSha256(useStrongBox)
        val limitedUseEc = limitedUseEc(useStrongBox)
        val ecdh = ecdhP256(useStrongBox)
        val rsaPss = rsaPssSha256(useStrongBox)
        val aesCbcCtr = aesCbcCtrRejected(useStrongBox)
        val aesCbcNoPadding = aesCbcNoPaddingRejected(useStrongBox)
        val ecSha512 = ecSha512Rejected(useStrongBox)
        val rsaPssSha512 = rsaPssSha512Rejected(useStrongBox)
        val rsaPssPkcs1 = rsaPssPkcs1Rejected(useStrongBox)
        val rsaOaepPkcs1 = rsaOaepPkcs1Rejected(useStrongBox)
        val rsaPkcs1Oaep = rsaPkcs1OaepRejected(useStrongBox)
        val rsaOaepMgf1 = rsaOaepMgf1Sha256(attestationVersion, useStrongBox)
        val rsaOaepMgf1Sha1 = rsaOaepMgf1Sha1Rejected(attestationVersion, useStrongBox)
        val rsaOaepSha256 = rsaOaepSha256RoundTrip(useStrongBox)
        val rsaOaepSha1 = rsaOaepSha1Rejected(useStrongBox)
        val ecNone = ecNoneRejected(useStrongBox)
        val rsaPkcs1Sha1 = rsaPkcs1Sha1Rejected(useStrongBox)
        val rsaPkcs1Pss = rsaPkcs1PssRejected(useStrongBox)
        val grantUpdateSubcomponent = grantUpdateSubcomponent(useStrongBox)
        return KeyMintCapabilityResult(
            executed = true,
            crypto = KeyMintCryptoCapabilityResult(
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
                aesCbcCtrExecuted = aesCbcCtr.executed,
                aesCbcCtrOk = aesCbcCtr.ok,
                aesCbcCtrDetail = aesCbcCtr.detail,
                aesCbcNoPaddingExecuted = aesCbcNoPadding.executed,
                aesCbcNoPaddingOk = aesCbcNoPadding.ok,
                aesCbcNoPaddingDetail = aesCbcNoPadding.detail,
                ecSha512Executed = ecSha512.executed,
                ecSha512Ok = ecSha512.ok,
                ecSha512Detail = ecSha512.detail,
                rsaPssSha512Executed = rsaPssSha512.executed,
                rsaPssSha512Ok = rsaPssSha512.ok,
                rsaPssSha512Detail = rsaPssSha512.detail,
                rsaPssPkcs1Executed = rsaPssPkcs1.executed,
                rsaPssPkcs1Ok = rsaPssPkcs1.ok,
                rsaPssPkcs1Detail = rsaPssPkcs1.detail,
                rsaOaepPkcs1Executed = rsaOaepPkcs1.executed,
                rsaOaepPkcs1Ok = rsaOaepPkcs1.ok,
                rsaOaepPkcs1Detail = rsaOaepPkcs1.detail,
                rsaPkcs1OaepExecuted = rsaPkcs1Oaep.executed,
                rsaPkcs1OaepOk = rsaPkcs1Oaep.ok,
                rsaPkcs1OaepDetail = rsaPkcs1Oaep.detail,
                rsaOaepMgf1Executed = rsaOaepMgf1.executed,
                rsaOaepMgf1Ok = rsaOaepMgf1.ok,
                rsaOaepMgf1Detail = rsaOaepMgf1.detail,
                rsaOaepMgf1Sha1Executed = rsaOaepMgf1Sha1.executed,
                rsaOaepMgf1Sha1Ok = rsaOaepMgf1Sha1.ok,
                rsaOaepMgf1Sha1Detail = rsaOaepMgf1Sha1.detail,
                rsaOaepSha256Executed = rsaOaepSha256.executed,
                rsaOaepSha256Ok = rsaOaepSha256.ok,
                rsaOaepSha256Detail = rsaOaepSha256.detail,
                rsaOaepSha1Executed = rsaOaepSha1.executed,
                rsaOaepSha1Ok = rsaOaepSha1.ok,
                rsaOaepSha1Detail = rsaOaepSha1.detail,
                ecNoneExecuted = ecNone.executed,
                ecNoneOk = ecNone.ok,
                ecNoneDetail = ecNone.detail,
                rsaPkcs1Sha1Executed = rsaPkcs1Sha1.executed,
                rsaPkcs1Sha1Ok = rsaPkcs1Sha1.ok,
                rsaPkcs1Sha1Detail = rsaPkcs1Sha1.detail,
                rsaPkcs1PssExecuted = rsaPkcs1Pss.executed,
                rsaPkcs1PssOk = rsaPkcs1Pss.ok,
                rsaPkcs1PssDetail = rsaPkcs1Pss.detail,
                grantUpdateSubcomponentExecuted = grantUpdateSubcomponent.executed,
                grantUpdateSubcomponentOk = grantUpdateSubcomponent.ok,
                grantUpdateSubcomponentDetail = grantUpdateSubcomponent.detail,
            ),
        )
    }

    private fun grantUpdateSubcomponent(useStrongBox: Boolean): CheckResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return CheckResult(
                ok = true,
                detail = "Grant updateSubcomponent requires Android 12 or newer.",
                executed = false,
            )
        }
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duck_grant_update_${System.nanoTime()}"
        val binderClient = Keystore2PrivateBinderClient()
        val grantClient = Keystore2PrivateGrantClient(binderClient)
        val random = java.security.SecureRandom()
        val markerCert = ByteArray(32).also(random::nextBytes)
        val markerChain = ByteArray(32).also(random::nextBytes)
        var grantCreated = false
        return try {
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = "CN=Duck Grant Update, O=Eltavine",
                useStrongBox = useStrongBox,
            )
            val service = binderClient.getKeystoreService() ?: return CheckResult(
                ok = true,
                detail = "Grant updateSubcomponent skipped: Keystore2 service unavailable.",
                executed = false,
            )
            val constants = grantClient.constantsSnapshot()
            val grant = grantClient.grantAliasToUid(
                service = service,
                alias = alias,
                uid = Process.myUid(),
                accessVector = constants.permissionGetInfo or constants.permissionUpdate,
            )
            val grantId = grant.grantId
            if (!grant.available || grantId == null) {
                return CheckResult(
                    ok = true,
                    detail = "Grant updateSubcomponent skipped: ${grant.detail}",
                    executed = false,
                )
            }
            grantCreated = true
            val grantDescriptor = grantClient.createGrantDescriptor(grantId)
            val updateFailure = runCatching {
                service.javaClass
                    .getMethod(
                        "updateSubcomponent",
                        grantDescriptor.javaClass,
                        ByteArray::class.java,
                        ByteArray::class.java,
                    )
                    .invoke(service, grantDescriptor, markerCert, markerChain)
            }.exceptionOrNull()
            if (updateFailure != null) {
                return CheckResult(
                    ok = false,
                    detail = "Grant updateSubcomponent failed after grant: ${binderClient.describeThrowable(updateFailure)}",
                )
            }
            val response = binderClient.getKeyEntryResponse(service, grantDescriptor)
                ?: return CheckResult(false, "Grant updateSubcomponent readback returned no KeyEntryResponse.")
            val appResponse = binderClient.getKeyEntryResponse(service, binderClient.createKeyDescriptor(alias))
                ?: return CheckResult(false, "Grant updateSubcomponent APP readback returned no KeyEntryResponse.")
            val certMatches = binderClient.getCertificateBlob(response)?.contentEquals(markerCert) == true
            val chainMatches = binderClient.getCertificateChainBlob(response)?.contentEquals(markerChain) == true
            val appCertMatches = binderClient.getCertificateBlob(appResponse)?.contentEquals(markerCert) == true
            val appChainMatches = binderClient.getCertificateChainBlob(appResponse)?.contentEquals(markerChain) == true
            CheckResult(
                ok = certMatches && chainMatches && appCertMatches && appChainMatches,
                detail = "grantUpdateSubcomponent certMatches=$certMatches, chainMatches=$chainMatches, " +
                    "appCertMatches=$appCertMatches, appChainMatches=$appChainMatches.",
            )
        } catch (throwable: Throwable) {
            if (grantCreated) {
                CheckResult(false, "Grant updateSubcomponent failed after grant: ${binderClient.describeThrowable(throwable)}")
            } else {
                CheckResult(
                    ok = true,
                    detail = "Grant updateSubcomponent skipped: ${binderClient.describeThrowable(throwable)}",
                    executed = false,
                )
            }
        } finally {
            if (grantCreated) {
                runCatching { grantClient.revokeAliasGrant(alias = alias, uid = Process.myUid()) }
            }
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
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
            val firstUseOk = sign(key, SIGNATURE_ECDSA_SHA256, "first")
            val secondUseOk = sign(key, SIGNATURE_ECDSA_SHA256, "second")
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

    private fun aesCbcCtrRejected(useStrongBox: Boolean): CheckResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_aesctr_${System.nanoTime()}"
        return try {
            val key = generateAesKey(alias, useStrongBox) {
                setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                setRandomizedEncryptionRequired(false)
            }
            val payload = "duck_aes_ctr".encodeToByteArray()
            val params = IvParameterSpec(ByteArray(16) { it.toByte() })
            val succeeded = encrypt(key, "AES/CTR/NoPadding", payload, params) != null
            CheckResult(!succeeded, "unauthorizedEncryptSucceeded=$succeeded.")
        } catch (throwable: Throwable) {
            skipped("AES-CBC CTR authorization", throwable)
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun aesCbcNoPaddingRejected(useStrongBox: Boolean): CheckResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_aesnopad_${System.nanoTime()}"
        return try {
            val key = generateAesKey(alias, useStrongBox) {
                setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                setRandomizedEncryptionRequired(false)
            }
            val payload = ByteArray(16) { it.toByte() }
            val params = IvParameterSpec(ByteArray(16) { (it + 1).toByte() })
            val succeeded = encrypt(key, "AES/CBC/NoPadding", payload, params) != null
            CheckResult(!succeeded, "unauthorizedEncryptSucceeded=$succeeded.")
        } catch (throwable: Throwable) {
            skipped("AES-CBC NoPadding authorization", throwable)
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun ecSha512Rejected(useStrongBox: Boolean): CheckResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_ecdigest_${System.nanoTime()}"
        return try {
            val keyPair = generateEcKeyPair(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                useStrongBox,
            )
            val succeeded = sign(keyPair.private, "SHA512withECDSA", "ec_sha512")
            CheckResult(!succeeded, "unauthorizedSignSucceeded=$succeeded.")
        } catch (throwable: Throwable) {
            skipped("EC SHA-512 authorization", throwable)
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun rsaPssSha512Rejected(useStrongBox: Boolean): CheckResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_rsapssdigest_${System.nanoTime()}"
        return try {
            val keyPair = generateRsaKeyPair(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                useStrongBox,
            ) {
                setDigests(KeyProperties.DIGEST_SHA256)
                setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
            }
            val succeeded = sign(keyPair.private, "SHA512withRSA/PSS", "rsa_pss_sha512")
            CheckResult(!succeeded, "unauthorizedSignSucceeded=$succeeded.")
        } catch (throwable: Throwable) {
            skipped("RSA-PSS SHA-512 authorization", throwable)
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun rsaPssPkcs1Rejected(useStrongBox: Boolean): CheckResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_rsapkcs1sig_${System.nanoTime()}"
        return try {
            val keyPair = generateRsaKeyPair(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                useStrongBox,
            ) {
                setDigests(KeyProperties.DIGEST_SHA256)
                setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
            }
            val succeeded = sign(keyPair.private, "SHA256withRSA", "rsa_pkcs1")
            CheckResult(!succeeded, "unauthorizedSignSucceeded=$succeeded.")
        } catch (throwable: Throwable) {
            skipped("RSA-PSS PKCS#1 authorization", throwable)
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun rsaOaepPkcs1Rejected(useStrongBox: Boolean): CheckResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_rsapadding_${System.nanoTime()}"
        return try {
            val keyPair = generateRsaKeyPair(alias, KeyProperties.PURPOSE_DECRYPT, useStrongBox) {
                setDigests(KeyProperties.DIGEST_SHA256)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            }
            val payload = "duck_rsa_padding".encodeToByteArray()
            val encrypted = encrypt(rsaPublicKey(keyPair), CIPHER_RSA_PKCS1, payload)
                ?: return CheckResult(
                    ok = true,
                    detail = "RSA PKCS#1 encryption unavailable.",
                    executed = false,
                )
            val succeeded = decrypt(keyPair.private, CIPHER_RSA_PKCS1, encrypted) != null
            CheckResult(!succeeded, "unauthorizedDecryptSucceeded=$succeeded.")
        } catch (throwable: Throwable) {
            skipped("RSA-OAEP PKCS#1 authorization", throwable)
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun rsaPkcs1OaepRejected(useStrongBox: Boolean): CheckResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_rsaoaep_${System.nanoTime()}"
        return try {
            val keyPair = generateRsaKeyPair(alias, KeyProperties.PURPOSE_DECRYPT, useStrongBox) {
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            }
            val payload = "duck_rsa_oaep_padding".encodeToByteArray()
            val encrypted = encrypt(rsaPublicKey(keyPair), CIPHER_RSA_OAEP_SHA1_MGF1, payload)
                ?: return CheckResult(
                    ok = true,
                    detail = "RSA-OAEP SHA-1 encryption unavailable.",
                    executed = false,
                )
            val succeeded = decrypt(keyPair.private, CIPHER_RSA_OAEP_SHA1_MGF1, encrypted) != null
            CheckResult(!succeeded, "unauthorizedDecryptSucceeded=$succeeded.")
        } catch (throwable: Throwable) {
            skipped("RSA-PKCS#1 OAEP authorization", throwable)
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun rsaOaepMgf1Sha256(attestationVersion: Int, useStrongBox: Boolean): CheckResult {
        if (Build.VERSION.SDK_INT < 35) {
            return CheckResult(
                ok = true,
                detail = "RSA-OAEP MGF1 digest probe requires Android 15 or newer.",
                executed = false,
            )
        }
        if (attestationVersion < 100) {
            return CheckResult(
                ok = true,
                detail = "RSA-OAEP MGF1 digest probe requires KeyMint 1.0 or newer.",
                executed = false,
            )
        }
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_rsamgf_${System.nanoTime()}"
        return try {
            val keyPair = generateRsaKeyPair(alias, KeyProperties.PURPOSE_DECRYPT, useStrongBox) {
                setDigests(KeyProperties.DIGEST_SHA256)
                setMgf1Digests(KeyProperties.DIGEST_SHA256)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            }
            val payload = "duck_rsa_oaep_mgf1".encodeToByteArray()
            val params = oaepSha256Mgf1Sha256()
            val encrypted = encrypt(
                rsaPublicKey(keyPair),
                CIPHER_RSA_OAEP_SHA256_MGF1,
                payload,
                params,
            ) ?: return CheckResult(
                ok = true,
                detail = "RSA-OAEP SHA-256 encryption unavailable.",
                executed = false,
            )
            val decrypted = decrypt(
                keyPair.private,
                CIPHER_RSA_OAEP_SHA256_MGF1,
                encrypted,
                params,
            )
            val roundTrip = decrypted?.contentEquals(payload) == true
            CheckResult(roundTrip, "roundTrip=$roundTrip, decryptedBytes=${decrypted?.size ?: 0}.")
        } catch (throwable: Throwable) {
            skipped("RSA-OAEP MGF1 SHA-256", throwable)
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun rsaOaepMgf1Sha1Rejected(attestationVersion: Int, useStrongBox: Boolean): CheckResult {
        if (Build.VERSION.SDK_INT < 35) {
            return CheckResult(
                ok = true,
                detail = "RSA-OAEP MGF1 digest authorization probe requires Android 15 or newer.",
                executed = false,
            )
        }
        if (attestationVersion < 100) {
            return CheckResult(
                ok = true,
                detail = "RSA-OAEP MGF1 digest authorization probe requires KeyMint 1.0 or newer.",
                executed = false,
            )
        }
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_rsamgfsha1_${System.nanoTime()}"
        return try {
            val keyPair = generateRsaKeyPair(alias, KeyProperties.PURPOSE_DECRYPT, useStrongBox) {
                setDigests(KeyProperties.DIGEST_SHA1)
                setMgf1Digests(KeyProperties.DIGEST_SHA256)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            }
            val payload = "duck_rsa_oaep_mgf1_sha1".encodeToByteArray()
            val encrypted = encrypt(rsaPublicKey(keyPair), CIPHER_RSA_OAEP_SHA1_MGF1, payload)
                ?: return CheckResult(
                    ok = true,
                    detail = "RSA-OAEP SHA-1 encryption unavailable.",
                    executed = false,
                )
            val succeeded = decrypt(keyPair.private, CIPHER_RSA_OAEP_SHA1_MGF1, encrypted) != null
            CheckResult(!succeeded, "unauthorizedDecryptSucceeded=$succeeded.")
        } catch (throwable: Throwable) {
            skipped("RSA-OAEP MGF1 SHA-1 authorization", throwable)
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun rsaOaepSha256RoundTrip(useStrongBox: Boolean): CheckResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_oaep_sha256_${System.nanoTime()}"
        return try {
            val keyPair = generateRsaKeyPair(alias, KeyProperties.PURPOSE_DECRYPT, useStrongBox) {
                setDigests(KeyProperties.DIGEST_SHA256)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            }
            val payload = "duck_oaep_sha256".encodeToByteArray()
            val params = oaepSha256Mgf1Sha1()
            val encrypted = encrypt(rsaPublicKey(keyPair), CIPHER_RSA_OAEP_SHA256_MGF1, payload, params)
                ?: return CheckResult(false, "RSA-OAEP SHA-256 encryption unavailable.")
            val decrypted = decrypt(keyPair.private, CIPHER_RSA_OAEP_SHA256_MGF1, encrypted, params)
            val roundTrip = decrypted?.contentEquals(payload) == true
            CheckResult(roundTrip, "roundTrip=$roundTrip, decryptedBytes=${decrypted?.size ?: 0}.")
        } catch (throwable: Throwable) {
            CheckResult(false, throwable.message ?: "RSA-OAEP SHA-256 round-trip failed.")
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun rsaOaepSha1Rejected(useStrongBox: Boolean): CheckResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_oaep_sha1_${System.nanoTime()}"
        return try {
            val keyPair = generateRsaKeyPair(alias, KeyProperties.PURPOSE_DECRYPT, useStrongBox) {
                setDigests(KeyProperties.DIGEST_SHA256)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            }
            val payload = "duck_oaep_sha1".encodeToByteArray()
            val encrypted = encrypt(rsaPublicKey(keyPair), CIPHER_RSA_OAEP_SHA1_MGF1, payload)
                ?: return CheckResult(false, "RSA-OAEP SHA-1 encryption unavailable.")
            val succeeded = decrypt(keyPair.private, CIPHER_RSA_OAEP_SHA1_MGF1, encrypted) != null
            CheckResult(!succeeded, "unauthorizedDecryptSucceeded=$succeeded.")
        } catch (throwable: Throwable) {
            CheckResult(false, throwable.message ?: "RSA-OAEP SHA-1 rejection probe failed.")
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun ecNoneRejected(useStrongBox: Boolean): CheckResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_ecnone_${System.nanoTime()}"
        return try {
            val keyPair = generateEcKeyPair(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                useStrongBox,
            )
            val succeeded = sign(keyPair.private, "NONEwithECDSA", "ec_none")
            CheckResult(!succeeded, "unauthorizedSignSucceeded=$succeeded.")
        } catch (throwable: Throwable) {
            CheckResult(false, throwable.message ?: "EC NONE digest probe failed.")
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun rsaPkcs1Sha1Rejected(useStrongBox: Boolean): CheckResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_rsapkcs1sha1_${System.nanoTime()}"
        return try {
            val keyPair = generateRsaKeyPair(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                useStrongBox,
            ) {
                setDigests(KeyProperties.DIGEST_SHA256)
                setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            }
            val succeeded = sign(keyPair.private, "SHA1withRSA", "rsa_pkcs1_sha1")
            CheckResult(!succeeded, "unauthorizedSignSucceeded=$succeeded.")
        } catch (throwable: Throwable) {
            CheckResult(false, throwable.message ?: "RSA PKCS#1 SHA-1 probe failed.")
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun rsaPkcs1PssRejected(useStrongBox: Boolean): CheckResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "duck_keymint_rsapkcs1pss_${System.nanoTime()}"
        return try {
            val keyPair = generateRsaKeyPair(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                useStrongBox,
            ) {
                setDigests(KeyProperties.DIGEST_SHA256)
                setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            }
            val succeeded = sign(keyPair.private, "SHA256withRSA/PSS", "rsa_pkcs1_pss")
            CheckResult(!succeeded, "unauthorizedSignSucceeded=$succeeded.")
        } catch (throwable: Throwable) {
            CheckResult(false, throwable.message ?: "RSA PKCS#1/PSS probe failed.")
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun sign(key: PrivateKey, algorithm: String, label: String): Boolean = runCatching {
        val signer = Signature.getInstance(algorithm)
        signer.initSign(key)
        signer.update("duck_usage_$label".encodeToByteArray())
        signer.sign()
        true
    }.getOrDefault(false)

    private fun generateEcKeyPair(
        alias: String,
        purposes: Int,
        useStrongBox: Boolean,
        configure: KeyGenParameterSpec.Builder.() -> Unit = {},
    ): KeyPair {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore",
        )
        val builder = KeyGenParameterSpec.Builder(alias, purposes)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setCertificateSubject(X500Principal("CN=DuckDetector KeyMint Probe, O=Eltavine"))
            .setCertificateSerialNumber(BigInteger.valueOf(System.nanoTime()))
            .setCertificateNotBefore(Calendar.getInstance().time)
            .setCertificateNotAfter(Calendar.getInstance().apply { add(Calendar.YEAR, 1) }.time)
            .setAttestationChallenge("duck_keymint_probe".encodeToByteArray())
            .setDigests(KeyProperties.DIGEST_SHA256)
        builder.configure()
        applyStrongBox(builder, useStrongBox)
        generator.initialize(builder.build())
        return generator.generateKeyPair()
    }

    private fun generateRsaKeyPair(
        alias: String,
        purposes: Int,
        useStrongBox: Boolean,
        configure: KeyGenParameterSpec.Builder.() -> Unit,
    ): KeyPair {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            "AndroidKeyStore",
        )
        val builder = KeyGenParameterSpec.Builder(alias, purposes).setKeySize(2048)
            .setCertificateSubject(X500Principal("CN=DuckDetector KeyMint Probe, O=Eltavine"))
            .setCertificateSerialNumber(BigInteger.valueOf(System.nanoTime()))
            .setCertificateNotBefore(Calendar.getInstance().time)
            .setCertificateNotAfter(Calendar.getInstance().apply { add(Calendar.YEAR, 1) }.time)
            .setAttestationChallenge("duck_keymint_probe".encodeToByteArray())
        builder.configure()
        applyStrongBox(builder, useStrongBox)
        generator.initialize(builder.build())
        return generator.generateKeyPair()
    }

    private fun generateAesKey(
        alias: String,
        useStrongBox: Boolean,
        configure: KeyGenParameterSpec.Builder.() -> Unit,
    ): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        ).setKeySize(128)
        builder.configure()
        applyStrongBox(builder, useStrongBox)
        generator.init(builder.build())
        return generator.generateKey()
    }

    private fun applyStrongBox(builder: KeyGenParameterSpec.Builder, useStrongBox: Boolean) {
        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
    }

    private fun rsaPublicKey(keyPair: KeyPair): PublicKey =
        KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(keyPair.public.encoded))

    private fun encrypt(
        key: Key,
        transform: String,
        payload: ByteArray,
        params: AlgorithmParameterSpec? = null,
    ): ByteArray? = runCatching {
        Cipher.getInstance(transform).apply {
            if (params == null) init(Cipher.ENCRYPT_MODE, key) else init(Cipher.ENCRYPT_MODE, key, params)
        }.doFinal(payload)
    }.getOrNull()

    private fun decrypt(
        key: PrivateKey,
        transform: String,
        payload: ByteArray,
        params: AlgorithmParameterSpec? = null,
    ): ByteArray? = runCatching {
        Cipher.getInstance(transform).apply {
            if (params == null) init(Cipher.DECRYPT_MODE, key) else init(Cipher.DECRYPT_MODE, key, params)
        }.doFinal(payload)
    }.getOrNull()

    private fun oaepSha256Mgf1Sha256(): OAEPParameterSpec =
        OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT,
        )

    private fun oaepSha256Mgf1Sha1(): OAEPParameterSpec =
        OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT,
        )

    private fun skipped(name: String, throwable: Throwable): CheckResult =
        CheckResult(
            ok = true,
            detail = "${throwable.message ?: "$name unavailable."}",
            executed = false,
        )

    private data class CheckResult(
        val ok: Boolean,
        val detail: String,
        val executed: Boolean = true,
    )
}

data class KeyMintCapabilityResult(
    val executed: Boolean,
    val crypto: KeyMintCryptoCapabilityResult = KeyMintCryptoCapabilityResult(),
)

data class KeyMintCryptoCapabilityResult(
    val hmacSha256Ok: Boolean = true,
    val hmacSha256Detail: String = "HMAC-SHA256 skipped.",
    val limitedUseEcExecuted: Boolean = true,
    val limitedUseEcOk: Boolean = true,
    val limitedUseEcDetail: String = "Single-use EC skipped.",
    val ecdhP256Executed: Boolean = true,
    val ecdhP256Ok: Boolean = true,
    val ecdhP256Detail: String = "ECDH P-256 skipped.",
    val rsaPssSha256Ok: Boolean = true,
    val rsaPssSha256Detail: String = "RSA-PSS SHA-256 skipped.",
    val aesCbcCtrExecuted: Boolean = true,
    val aesCbcCtrOk: Boolean = true,
    val aesCbcCtrDetail: String = "AES-CBC CTR authorization skipped.",
    val aesCbcNoPaddingExecuted: Boolean = true,
    val aesCbcNoPaddingOk: Boolean = true,
    val aesCbcNoPaddingDetail: String = "AES-CBC NoPadding authorization skipped.",
    val ecSha512Executed: Boolean = true,
    val ecSha512Ok: Boolean = true,
    val ecSha512Detail: String = "EC SHA-512 authorization skipped.",
    val rsaPssSha512Executed: Boolean = true,
    val rsaPssSha512Ok: Boolean = true,
    val rsaPssSha512Detail: String = "RSA-PSS SHA-512 authorization skipped.",
    val rsaPssPkcs1Executed: Boolean = true,
    val rsaPssPkcs1Ok: Boolean = true,
    val rsaPssPkcs1Detail: String = "RSA-PSS PKCS#1 authorization skipped.",
    val rsaOaepPkcs1Executed: Boolean = true,
    val rsaOaepPkcs1Ok: Boolean = true,
    val rsaOaepPkcs1Detail: String = "RSA-OAEP PKCS#1 authorization skipped.",
    val rsaPkcs1OaepExecuted: Boolean = true,
    val rsaPkcs1OaepOk: Boolean = true,
    val rsaPkcs1OaepDetail: String = "RSA-PKCS#1 OAEP authorization skipped.",
    val rsaOaepMgf1Executed: Boolean = true,
    val rsaOaepMgf1Ok: Boolean = true,
    val rsaOaepMgf1Detail: String = "RSA-OAEP MGF1 skipped.",
    val rsaOaepMgf1Sha1Executed: Boolean = true,
    val rsaOaepMgf1Sha1Ok: Boolean = true,
    val rsaOaepMgf1Sha1Detail: String = "RSA-OAEP MGF1 SHA-1 authorization skipped.",
    val rsaOaepSha256Executed: Boolean = true,
    val rsaOaepSha256Ok: Boolean = true,
    val rsaOaepSha256Detail: String = "RSA-OAEP SHA-256 skipped.",
    val rsaOaepSha1Executed: Boolean = true,
    val rsaOaepSha1Ok: Boolean = true,
    val rsaOaepSha1Detail: String = "RSA-OAEP SHA-1 authorization skipped.",
    val ecNoneExecuted: Boolean = true,
    val ecNoneOk: Boolean = true,
    val ecNoneDetail: String = "EC NONE digest authorization skipped.",
    val rsaPkcs1Sha1Executed: Boolean = true,
    val rsaPkcs1Sha1Ok: Boolean = true,
    val rsaPkcs1Sha1Detail: String = "RSA PKCS#1 SHA-1 authorization skipped.",
    val rsaPkcs1PssExecuted: Boolean = true,
    val rsaPkcs1PssOk: Boolean = true,
    val rsaPkcs1PssDetail: String = "RSA PKCS#1/PSS authorization skipped.",
    val grantUpdateSubcomponentExecuted: Boolean = true,
    val grantUpdateSubcomponentOk: Boolean = true,
    val grantUpdateSubcomponentDetail: String = "Grant updateSubcomponent skipped.",
)

private const val SIGNATURE_ECDSA_SHA256 = "SHA256withECDSA"
private const val CIPHER_RSA_PKCS1 = "RSA/ECB/PKCS1Padding"
private const val CIPHER_RSA_OAEP_SHA1_MGF1 = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"
private const val CIPHER_RSA_OAEP_SHA256_MGF1 = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
