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
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
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

class KeyMintCapabilityProbe(
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
) {
    fun inspect(
        attestationVersion: Int? = null,
        keymasterVersion: Int? = null,
        declaredKeyMintVersion: Int? = null,
        legacyKeymasterDeclared: Boolean = false,
        securityLevelsConsistent: Boolean = true,
        useStrongBox: Boolean = false,
    ): KeyMintCapabilityResult {
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
        val rsaOaepMgf1 = rsaOaepMgf1Sha256(
            attestationVersion,
            keymasterVersion,
            declaredKeyMintVersion,
            legacyKeymasterDeclared,
            securityLevelsConsistent,
            useStrongBox,
        )
        val rsaOaepMgf1Sha1 = rsaOaepMgf1Sha1Rejected(
            attestationVersion,
            keymasterVersion,
            declaredKeyMintVersion,
            legacyKeymasterDeclared,
            securityLevelsConsistent,
            useStrongBox,
        )
        val rsaOaepSha256 = rsaOaepSha256RoundTrip(useStrongBox)
        val rsaOaepSha1 = rsaOaepSha1Rejected(useStrongBox)
        val ecNone = ecNoneRejected(useStrongBox)
        val rsaPkcs1Sha1 = rsaPkcs1Sha1Rejected(useStrongBox)
        val rsaPkcs1Pss = rsaPkcs1PssRejected(useStrongBox)
        val grantUpdateSubcomponent = grantUpdateSubcomponent(useStrongBox)
        val crypto = KeyMintCryptoCapabilityResult(
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
            )
        return KeyMintCapabilityResult(
            executed = true,
            crypto = crypto,
            diagnosticCopyText = buildKeyMintDiagnosticCopyText(
                sdkInt = Build.VERSION.SDK_INT,
                useStrongBox = useStrongBox,
                attestationVersion = attestationVersion,
                keymasterVersion = keymasterVersion,
                declaredKeyMintVersion = declaredKeyMintVersion,
                legacyKeymasterDeclared = legacyKeymasterDeclared,
                securityLevelsConsistent = securityLevelsConsistent,
                checks = listOf(
                    KeyMintDiagnosticEntry("HMAC-SHA256", hmac.executed, hmac.ok, hmac.detail, hmac.diagnostic),
                    KeyMintDiagnosticEntry("Single-use EC", limitedUseEc.executed, limitedUseEc.ok, limitedUseEc.detail, limitedUseEc.diagnostic),
                    KeyMintDiagnosticEntry("ECDH P-256", ecdh.executed, ecdh.ok, ecdh.detail, ecdh.diagnostic),
                    KeyMintDiagnosticEntry("RSA-PSS SHA-256", rsaPss.executed, rsaPss.ok, rsaPss.detail, rsaPss.diagnostic),
                    KeyMintDiagnosticEntry("AES-CBC/CTR auth", aesCbcCtr.executed, aesCbcCtr.ok, aesCbcCtr.detail, aesCbcCtr.diagnostic),
                    KeyMintDiagnosticEntry("AES-CBC padding auth", aesCbcNoPadding.executed, aesCbcNoPadding.ok, aesCbcNoPadding.detail, aesCbcNoPadding.diagnostic),
                    KeyMintDiagnosticEntry("EC SHA-512 auth", ecSha512.executed, ecSha512.ok, ecSha512.detail, ecSha512.diagnostic),
                    KeyMintDiagnosticEntry("RSA-PSS SHA-512 auth", rsaPssSha512.executed, rsaPssSha512.ok, rsaPssSha512.detail, rsaPssSha512.diagnostic),
                    KeyMintDiagnosticEntry("RSA-PSS PKCS#1 auth", rsaPssPkcs1.executed, rsaPssPkcs1.ok, rsaPssPkcs1.detail, rsaPssPkcs1.diagnostic),
                    KeyMintDiagnosticEntry("RSA OAEP/PKCS#1 auth", rsaOaepPkcs1.executed, rsaOaepPkcs1.ok, rsaOaepPkcs1.detail, rsaOaepPkcs1.diagnostic),
                    KeyMintDiagnosticEntry("RSA PKCS#1/OAEP auth", rsaPkcs1Oaep.executed, rsaPkcs1Oaep.ok, rsaPkcs1Oaep.detail, rsaPkcs1Oaep.diagnostic),
                    KeyMintDiagnosticEntry("RSA-OAEP MGF1", rsaOaepMgf1.executed, rsaOaepMgf1.ok, rsaOaepMgf1.detail, rsaOaepMgf1.diagnostic),
                    KeyMintDiagnosticEntry("RSA-OAEP MGF1 auth", rsaOaepMgf1Sha1.executed, rsaOaepMgf1Sha1.ok, rsaOaepMgf1Sha1.detail, rsaOaepMgf1Sha1.diagnostic),
                    KeyMintDiagnosticEntry("RSA-OAEP SHA-256", rsaOaepSha256.executed, rsaOaepSha256.ok, rsaOaepSha256.detail, rsaOaepSha256.diagnostic),
                    KeyMintDiagnosticEntry("RSA-OAEP SHA-1 auth", rsaOaepSha1.executed, rsaOaepSha1.ok, rsaOaepSha1.detail, rsaOaepSha1.diagnostic),
                    KeyMintDiagnosticEntry("EC NONE auth", ecNone.executed, ecNone.ok, ecNone.detail, ecNone.diagnostic),
                    KeyMintDiagnosticEntry("RSA PKCS#1 SHA-1 auth", rsaPkcs1Sha1.executed, rsaPkcs1Sha1.ok, rsaPkcs1Sha1.detail, rsaPkcs1Sha1.diagnostic),
                    KeyMintDiagnosticEntry("RSA PKCS#1/PSS auth", rsaPkcs1Pss.executed, rsaPkcs1Pss.ok, rsaPkcs1Pss.detail, rsaPkcs1Pss.diagnostic),
                    KeyMintDiagnosticEntry("Grant updateSubcomponent", grantUpdateSubcomponent.executed, grantUpdateSubcomponent.ok, grantUpdateSubcomponent.detail, grantUpdateSubcomponent.diagnostic),
                ),
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

    private fun rsaOaepMgf1Sha256(
        attestationVersion: Int?,
        keymasterVersion: Int?,
        declaredKeyMintVersion: Int?,
        legacyKeymasterDeclared: Boolean,
        securityLevelsConsistent: Boolean,
        useStrongBox: Boolean,
    ): CheckResult {
        if (!securityLevelsConsistent) {
            return CheckResult(false, "Attestation and keymaster security levels disagree.")
        }
        // We intentionally do not trust UI/API level alone here.
        // AndroidKeyStore only exposes MGF-digest configuration from newer framework APIs, but the
        // detection target is the backend KeyMint behavior, not the Java wrapper surface.
        // 因此这里不能只看 API level 或 Java API 是否暴露 setMgf1Digests；我们真正要验证的是
        // 后端 KeyMint/keystore2 的行为，而不是 framework 包装层是否恰好提供了公开入口。
        //
        // AOSP references:
        // frameworks/base/keystore/java/android/security/keystore2/AndroidKeyStoreRSACipherSpi.java
        // https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/keystore/java/android/security/keystore2/AndroidKeyStoreRSACipherSpi.java
        // hardware/interfaces/security/keymint/aidl/vts/functional/KeyMintTest.cpp
        // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/vts/functional/KeyMintTest.cpp
        val keyMintVersion = deriveObservedKeyMintVersion(
            attestationVersion,
            keymasterVersion,
            declaredKeyMintVersion,
        ) ?: KEYMINT_VERSION_1
        if (
            Build.VERSION.SDK_INT < Build.VERSION_CODES.S ||
            legacyKeymasterDeclared
        ) {
            return CheckResult(
                ok = true,
                detail = "RSA-OAEP MGF1 digest probe requires a native KeyMint 1+ backend.",
                executed = false,
            )
        }
        val alias = "duck_keymint_rsamgf_${System.nanoTime()}"
        return withRawRsaOaepKey(
            alias = alias,
            useStrongBox = useStrongBox,
            generationName = "Raw keystore2 RSA-OAEP key generation",
            probeName = "RSA-OAEP MGF1 SHA-256",
        ) { rawKey ->
            val capability = evaluateRsaOaepMgf1Capability(
                authorizations = rawKey.authorizations,
                attestationVersion,
                keymasterVersion,
                keyMintVersion,
                expectedSecurityLevel = rawKey.expectedSecurityLevel,
                returnedSecurityLevel = rawKey.returnedSecurityLevel,
            )
            if (!capability.shouldExecute) {
                CheckResult(
                    ok = true,
                    detail = capability.detail,
                    executed = false,
                    diagnostic = capability.diagnostic,
                )
            } else if (!capability.supported) {
                CheckResult(ok = false, detail = capability.detail, diagnostic = capability.diagnostic)
            } else {
                val payload = "duck_rsa_oaep_mgf1".encodeToByteArray()
                val params = oaepSha256Mgf1Sha256()
                val encrypted = encrypt(
                    rawKey.publicKey,
                    CIPHER_RSA_OAEP_SHA256_MGF1,
                    payload,
                    params,
                )
                if (encrypted == null) {
                    CheckResult(false, "RSA-OAEP SHA-256 local encryption failed.")
                } else {
                    rawRsaOaepMgf1RoundTrip(rawKey, encrypted, payload)
                }
            }
        }
    }

    private fun rsaOaepMgf1Sha1Rejected(
        attestationVersion: Int?,
        keymasterVersion: Int?,
        declaredKeyMintVersion: Int?,
        legacyKeymasterDeclared: Boolean,
        securityLevelsConsistent: Boolean,
        useStrongBox: Boolean,
    ): CheckResult {
        if (!securityLevelsConsistent) {
            return CheckResult(false, "Attestation and keymaster security levels disagree.")
        }
        val keyMintVersion = deriveObservedKeyMintVersion(
            attestationVersion,
            keymasterVersion,
            declaredKeyMintVersion,
        ) ?: KEYMINT_VERSION_1
        if (
            Build.VERSION.SDK_INT < Build.VERSION_CODES.S ||
            legacyKeymasterDeclared
        ) {
            return CheckResult(
                ok = true,
                detail = "RSA-OAEP MGF1 authorization probe requires a native KeyMint 1+ backend.",
                executed = false,
            )
        }
        val alias = "duck_keymint_rsamgfsha1_${System.nanoTime()}"
        return withRawRsaOaepKey(
            alias = alias,
            useStrongBox = useStrongBox,
            generationName = "Raw keystore2 RSA-OAEP authorization key generation",
            probeName = "RSA-OAEP MGF1 authorization",
        ) { rawKey ->
            val capability = evaluateRsaOaepMgf1Capability(
                authorizations = rawKey.authorizations,
                attestationVersion,
                keymasterVersion,
                keyMintVersion,
                expectedSecurityLevel = rawKey.expectedSecurityLevel,
                returnedSecurityLevel = rawKey.returnedSecurityLevel,
            )
            if (!capability.shouldExecute) {
                CheckResult(
                    ok = true,
                    detail = capability.detail,
                    executed = false,
                    diagnostic = capability.diagnostic,
                )
            } else if (!capability.supported) {
                CheckResult(ok = false, detail = capability.detail, diagnostic = capability.diagnostic)
            } else {
                rawRsaOaepMgf1Rejected(rawKey)
            }
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

    private fun generateRawRsaOaepKey(alias: String, useStrongBox: Boolean): RawRsaOaepKey {
        // Raw generation is deliberate. For KeyMint 1/2, VTS allows RSA_OAEP_MGF_DIGEST to be absent
        // from key characteristics, so generating via AndroidKeyStore and only reading characteristics
        // would falsely classify a conformant implementation as unsupported.
        // 这里必须走私有 keystore2 generateKey，而不是只看 AndroidKeyStore characteristics：
        // 对 KeyMint 1/2 来说，VTS 明确允许 characteristics 里没有 RSA_OAEP_MGF_DIGEST，
        // 否则会把“规范允许的缺失”误判成“不支持 MGF1”。
        //
        // AOSP references:
        // security/keymint/aidl/vts/functional/KeyMintTest.cpp (RsaOaepMGFDigestDefaultSuccess / Fail)
        // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/vts/functional/KeyMintTest.cpp
        // system/hardware/interfaces/keystore2/aidl/android/system/keystore2/IKeystoreSecurityLevel.aidl
        // https://android.googlesource.com/platform/system/hardware/interfaces/+/refs/heads/main/keystore2/aidl/android/system/keystore2/IKeystoreSecurityLevel.aidl
        val service = binderClient.getKeystoreService()
            ?: throw IllegalStateException("keystore2 service unavailable for native KeyMint probe.")
        val expectedSecurityLevel = if (useStrongBox) {
            Keystore2PrivateBinderClient.SECURITY_LEVEL_STRONGBOX
        } else {
            Keystore2PrivateBinderClient.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        }
        val securityLevel = binderClient.resolveSecurityLevel(service, expectedSecurityLevel)
            ?: throw IllegalStateException("Selected native KeyMint security level unavailable.")
        val requestedDescriptor = binderClient.createKeyDescriptor(alias)
        return try {
            val generated = binderClient.generateRsaOaepKey(
                securityLevel = securityLevel,
                keyDescriptor = requestedDescriptor,
                mgfDigest = KEYMINT_DIGEST_SHA_256,
            ) ?: throw IllegalStateException("Raw keystore2 RSA-OAEP generation returned no metadata.")
            val metadata = binderClient.getMetadata(generated) ?: generated
            val returnedSecurityLevel = binderClient.getKeyMetadataSecurityLevel(metadata)
                ?: throw IllegalStateException("Raw keystore2 RSA-OAEP metadata omitted keySecurityLevel.")
            val certificate = binderClient.getCertificateBlob(generated)
                ?: throw IllegalStateException("Raw keystore2 RSA-OAEP generation returned no certificate.")
            val publicKey = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(certificate))
                .publicKey
            val authorizations = binderClient.getMetadataAuthorizations(metadata).mapNotNull { authorization ->
                authorization?.let {
                    val tag = binderClient.getAuthorizationTag(it) ?: return@let null
                    AuthorizationSummary(
                        tag = tag,
                        intValue = if (tag == KEYMINT_TAG_RSA_OAEP_MGF_DIGEST) {
                            binderClient.getAuthorizationDigestValue(it)
                        } else {
                            binderClient.getAuthorizationIntValue(it)
                        },
                        securityLevel = binderClient.getAuthorizationSecurityLevel(it),
                    )
                }
            }
            RawRsaOaepKey(
                service = service,
                cleanupDescriptor = requestedDescriptor,
                operationDescriptor = binderClient.resolveFollowUpDescriptor(requestedDescriptor, generated),
                securityLevel = securityLevel,
                expectedSecurityLevel = expectedSecurityLevel,
                returnedSecurityLevel = returnedSecurityLevel,
                publicKey = publicKey,
                authorizations = authorizations,
            )
        } catch (throwable: Throwable) {
            val cleanupFailure = binderClient.deleteKeyChecked(service, requestedDescriptor)
            if (cleanupFailure != null) {
                throw IllegalStateException(
                    "${binderClient.describeThrowable(throwable)}; partial-key cleanup failed: " +
                        binderClient.describeThrowable(cleanupFailure),
                )
            }
            throw throwable
        }
    }

    private fun withRawRsaOaepKey(
        alias: String,
        useStrongBox: Boolean,
        generationName: String,
        probeName: String,
        block: (RawRsaOaepKey) -> CheckResult,
    ): CheckResult {
        val rawKey = try {
            generateRawRsaOaepKey(alias, useStrongBox)
        } catch (throwable: Throwable) {
            return classifyMgfProbeFailure(generationName, throwable)
        }
        val result = try {
            block(rawKey)
        } catch (throwable: Throwable) {
            classifyMgfProbeFailure(probeName, throwable)
        }
        val cleanupFailure = binderClient.deleteKeyChecked(rawKey.service, rawKey.cleanupDescriptor)
        return if (cleanupFailure == null) {
            result
        } else {
            CheckResult(
                ok = false,
                detail = result.detail + "; key cleanup failed: " +
                    binderClient.describeThrowable(cleanupFailure),
                executed = result.executed,
                diagnostic = listOfNotNull(
                    result.diagnostic,
                    "cleanup=failed, error=${binderClient.describeThrowable(cleanupFailure)}",
                ).joinToString("; "),
            )
        }
    }

    private fun rawRsaOaepMgf1RoundTrip(
        rawKey: RawRsaOaepKey,
        encrypted: ByteArray,
        payload: ByteArray,
    ): CheckResult {
        val parameters = binderClient.createRsaOaepDecryptOperationParameters(
            digest = KEYMINT_DIGEST_SHA_256,
            mgfDigest = KEYMINT_DIGEST_SHA_256,
        )
        val operation = try {
            binderClient.getOperationHandle(
                binderClient.createOperation(rawKey.securityLevel, rawKey.operationDescriptor, parameters),
            ) ?: return CheckResult(
                false,
                "Raw keystore2 MGF1 createOperation returned no operation handle.",
                diagnostic = rawKey.operationDiagnostic("begin=no_handle, digest=4, mgfDigest=4"),
            )
        } catch (throwable: Throwable) {
            return CheckResult(
                false,
                "Raw keystore2 MGF1 SHA-256 begin failed: ${binderClient.describeThrowable(throwable)}",
                diagnostic = rawKey.operationDiagnostic(
                    "begin=failed, digest=4, mgfDigest=4, error=${binderClient.describeThrowable(throwable)}",
                ),
            )
        }
        return try {
            val decrypted = binderClient.finishOperation(operation, encrypted)
            val roundTrip = decrypted?.contentEquals(payload) == true
            CheckResult(
                roundTrip,
                "rawBegin=true, roundTrip=$roundTrip, decryptedBytes=${decrypted?.size ?: 0}.",
                diagnostic = rawKey.operationDiagnostic(
                    "begin=ok, finish=ok, digest=4, mgfDigest=4, ciphertextBytes=${encrypted.size}, " +
                        "plaintextBytes=${payload.size}, decryptedBytes=${decrypted?.size ?: 0}, roundTrip=$roundTrip",
                ),
            )
        } catch (throwable: Throwable) {
            CheckResult(
                false,
                "Raw keystore2 MGF1 SHA-256 finish failed: ${binderClient.describeThrowable(throwable)}",
                diagnostic = rawKey.operationDiagnostic(
                    "begin=ok, finish=failed, digest=4, mgfDigest=4, ciphertextBytes=${encrypted.size}, " +
                        "plaintextBytes=${payload.size}, error=${binderClient.describeThrowable(throwable)}",
                ),
            )
        } finally {
            runCatching { binderClient.abortOperation(operation) }
        }
    }

    private fun rawRsaOaepMgf1Rejected(rawKey: RawRsaOaepKey): CheckResult {
        // We intentionally mirror the VTS matrix instead of inventing a broader rejection set.
        // The point of this probe is to detect backend divergence from AOSP semantics, so each case here
        // corresponds to a tested AOSP expectation: default SHA-1 rejection when absent from the key,
        // explicit SHA-224 incompatibility, and Digest.NONE unsupported.
        // 这里刻意只复刻 VTS 已定义的拒绝矩阵，而不是自创更多 case；检测目标是确认设备是否
        // 偏离 AOSP 语义，因此每个 case 都必须有上游规范依据。
        //
        // AOSP reference:
        // hardware/interfaces/security/keymint/aidl/vts/functional/KeyMintTest.cpp
        // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/vts/functional/KeyMintTest.cpp
        val results = keyMintMgfRejectionCases().map { rejectionCase ->
            rawRsaOaepMgf1BeginRejected(rawKey, rejectionCase)
        }
        val failures = results.filterNot { it.ok }
        return CheckResult(
            ok = failures.isEmpty(),
            detail = results.joinToString("; ") { it.detail },
            diagnostic = results.mapNotNull { it.diagnostic }.joinToString(" | "),
        )
    }

    private fun rawRsaOaepMgf1BeginRejected(
        rawKey: RawRsaOaepKey,
        rejectionCase: MgfRejectionCase,
    ): CheckResult {
        val parameters = binderClient.createRsaOaepDecryptOperationParameters(
            digest = KEYMINT_DIGEST_SHA_256,
            mgfDigest = rejectionCase.mgfDigest,
        )
        return try {
            val operation = binderClient.getOperationHandle(
                binderClient.createOperation(rawKey.securityLevel, rawKey.operationDescriptor, parameters),
            )
            runCatching { binderClient.abortOperation(operation) }
            CheckResult(
                false,
                "${rejectionCase.name}=accepted",
                diagnostic = rawKey.operationDiagnostic(
                    "case=${rejectionCase.name}, begin=accepted, digest=4, " +
                        "mgfDigest=${rejectionCase.mgfDigest ?: "default"}",
                ),
            )
        } catch (throwable: Throwable) {
            if (!binderClient.isServiceSpecificException(throwable)) {
                return CheckResult(
                    false,
                    "${rejectionCase.name}=failed(${binderClient.describeThrowable(throwable)})",
                    diagnostic = rawKey.operationDiagnostic(
                        "case=${rejectionCase.name}, begin=failed, digest=4, " +
                            "mgfDigest=${rejectionCase.mgfDigest ?: "default"}, " +
                            "error=${binderClient.describeThrowable(throwable)}",
                    ),
                )
            }
            val errorCode = binderClient.extractServiceSpecificErrorCode(throwable)
            val expected = errorCode in rejectionCase.expectedErrorCodes
            CheckResult(
                expected,
                "${rejectionCase.name}=rejected(code=$errorCode, expected=$expected)",
                diagnostic = rawKey.operationDiagnostic(
                    "case=${rejectionCase.name}, begin=rejected, digest=4, " +
                        "mgfDigest=${rejectionCase.mgfDigest ?: "default"}, " +
                        "errorCode=$errorCode, expected=$expected",
                ),
            )
        }
    }

    private fun classifyMgfProbeFailure(name: String, throwable: Throwable): CheckResult {
        val error = binderClient.describeThrowable(throwable)
        return CheckResult(false, "$name failed: $error", diagnostic = "stage=$name, error=$error")
    }

    private fun buildKeyMintDiagnosticCopyText(
        sdkInt: Int,
        useStrongBox: Boolean,
        attestationVersion: Int?,
        keymasterVersion: Int?,
        declaredKeyMintVersion: Int?,
        legacyKeymasterDeclared: Boolean,
        securityLevelsConsistent: Boolean,
        checks: List<KeyMintDiagnosticEntry>,
    ): String = buildString {
        appendLine("keymint-capability-diagnostic=v1")
        appendLine("sdkInt=$sdkInt")
        appendLine("useStrongBox=$useStrongBox")
        appendLine("attestationVersion=${attestationVersion ?: "null"}")
        appendLine("keymasterVersion=${keymasterVersion ?: "null"}")
        appendLine("declaredKeyMintVersion=${declaredKeyMintVersion ?: "null"}")
        appendLine("legacyKeymasterDeclared=$legacyKeymasterDeclared")
        appendLine("securityLevelsConsistent=$securityLevelsConsistent")
        appendLine("checks:")
        checks.forEach { check ->
            appendLine("- ${check.name}: executed=${check.executed}, ok=${check.ok}, detail=${check.detail}")
            check.diagnostic?.takeIf { it.isNotBlank() }?.let { diagnostic ->
                appendLine("  diagnostic=$diagnostic")
            }
        }
    }

    private data class KeyMintDiagnosticEntry(
        val name: String,
        val executed: Boolean,
        val ok: Boolean,
        val detail: String,
        val diagnostic: String?,
    )

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
        val diagnostic: String? = null,
    )
}

data class KeyMintCapabilityResult(
    val executed: Boolean,
    val crypto: KeyMintCryptoCapabilityResult = KeyMintCryptoCapabilityResult(),
    val diagnosticCopyText: String = "",
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
private const val KEYMINT_TAG_RSA_OAEP_MGF_DIGEST = 0x200000CB

internal data class RsaOaepMgf1Capability(
    val supported: Boolean,
    val shouldExecute: Boolean,
    val detail: String,
    val diagnostic: String = "",
)

internal data class AuthorizationSummary(
    val tag: Int,
    val intValue: Int?,
    val securityLevel: Int?,
)

internal fun evaluateRsaOaepMgf1Capability(
    authorizations: List<AuthorizationSummary>,
    attestationVersion: Int?,
    keymasterVersion: Int?,
    declaredKeyMintVersion: Int? = null,
    expectedSecurityLevel: Int = KEYMINT_SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
    returnedSecurityLevel: Int = expectedSecurityLevel,
): RsaOaepMgf1Capability {
    // KeyMint 3+ tightened the contract: the allowed MGF digests must be surfaced back through
    // hardware-enforced key characteristics, and VTS compares the exact set.
    // KeyMint 1/2 does not have that characteristics contract, so we switch to runtime operation tests.
    // KeyMint 3+ 必须在硬件强制的 key characteristics 中回显允许的 MGF digest 集合，VTS 会比对
    // 精确集合；而 KeyMint 1/2 没有这个 contract，所以我们退回到运行时 begin/finish 语义检测。
    //
    // AOSP references:
    // hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Tag.aidl
    // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/android/hardware/security/keymint/Tag.aidl
    // hardware/interfaces/security/keymint/aidl/vts/functional/KeyMintTest.cpp
    // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/vts/functional/KeyMintTest.cpp
    val diagnostic = buildString {
        append("observedKeyMintVersion=")
        append(deriveObservedKeyMintVersion(attestationVersion, keymasterVersion, declaredKeyMintVersion) ?: "null")
        append(", expectedSecurityLevel=")
        append(expectedSecurityLevel)
        append(", returnedSecurityLevel=")
        append(returnedSecurityLevel)
        append(", authorizations=")
        append(
            authorizations.joinToString { authorization ->
                "tag=0x${authorization.tag.toUInt().toString(16)}," +
                    "value=${authorization.intValue ?: "null"}," +
                    "securityLevel=${authorization.securityLevel ?: "null"}"
            }.ifBlank { "none" },
        )
    }
    val keyMintVersion = deriveObservedKeyMintVersion(
        attestationVersion,
        keymasterVersion,
        declaredKeyMintVersion,
    )
    if (keyMintVersion == null || keyMintVersion < 100) {
        return RsaOaepMgf1Capability(
            supported = false,
            shouldExecute = false,
            detail = "RSA-OAEP MGF1 skipped for legacy Keymaster/km_compat.",
            diagnostic = diagnostic,
        )
    }
    if (returnedSecurityLevel != expectedSecurityLevel) {
        return RsaOaepMgf1Capability(
            supported = false,
            shouldExecute = true,
            detail = "Generated key security level=$returnedSecurityLevel; expected=$expectedSecurityLevel.",
            diagnostic = diagnostic,
        )
    }
    if (keyMintVersion < 300) {
        return RsaOaepMgf1Capability(
            supported = true,
            shouldExecute = true,
            detail = "KeyMint 1/2 uses raw keystore2 operation checks; characteristics are not required by VTS.",
            diagnostic = diagnostic,
        )
    }
    val mgfAuthorizations = authorizations.filter { it.tag == KEYMINT_TAG_RSA_OAEP_MGF_DIGEST }
    if (mgfAuthorizations.isEmpty()) {
        return RsaOaepMgf1Capability(
            supported = false,
            shouldExecute = true,
            detail = "Generated key characteristics omit RSA_OAEP_MGF_DIGEST on KeyMint 3+.",
            diagnostic = diagnostic,
        )
    }
    val wrongSecurityLevel = mgfAuthorizations.any { it.securityLevel != expectedSecurityLevel }
    if (wrongSecurityLevel) {
        return RsaOaepMgf1Capability(
            supported = false,
            shouldExecute = true,
            detail = "RSA_OAEP_MGF_DIGEST was not enforced by the selected hardware security level.",
            diagnostic = diagnostic,
        )
    }
    val observedDigests = mgfAuthorizations.mapNotNull { it.intValue }
    if (observedDigests != listOf(KEYMINT_DIGEST_SHA_256) || mgfAuthorizations.any { it.intValue == null }) {
        return RsaOaepMgf1Capability(
            supported = false,
            shouldExecute = true,
            detail = "Generated key characteristics expose MGF1 digests=$observedDigests; expected=[${KEYMINT_DIGEST_SHA_256}].",
            diagnostic = diagnostic,
        )
    }
    return RsaOaepMgf1Capability(
        supported = true,
        shouldExecute = true,
        detail = "Generated key characteristics exactly match hardware-enforced MGF1 SHA-256.",
        diagnostic = diagnostic,
    )
}

internal fun isKeyMintOneOrTwo(
    attestationVersion: Int?,
    keymasterVersion: Int?,
    declaredKeyMintVersion: Int? = null,
): Boolean {
    return deriveObservedKeyMintVersion(
        attestationVersion,
        keymasterVersion,
        declaredKeyMintVersion,
    ) in 100..299
}

internal data class MgfRejectionCase(
    val name: String,
    val mgfDigest: Int?,
    val expectedErrorCodes: Set<Int>,
)

internal fun keyMintMgfRejectionCases(): List<MgfRejectionCase> {
    val incompatibleOrUnsupported = setOf(
        KEYMINT_ERROR_INCOMPATIBLE_MGF_DIGEST,
        KEYMINT_ERROR_UNSUPPORTED_MGF_DIGEST,
    )
    return listOf(
        MgfRejectionCase("default-sha1", null, incompatibleOrUnsupported),
        MgfRejectionCase(
            "explicit-sha224",
            KEYMINT_DIGEST_SHA_224,
            setOf(KEYMINT_ERROR_INCOMPATIBLE_MGF_DIGEST),
        ),
        MgfRejectionCase(
            "unsupported-none",
            KEYMINT_DIGEST_NONE,
            setOf(KEYMINT_ERROR_UNSUPPORTED_MGF_DIGEST),
        ),
    )
}

internal fun deriveObservedKeyMintVersion(
    attestationVersion: Int?,
    keymasterVersion: Int?,
    declaredKeyMintVersion: Int? = null,
): Int? {
    // We take the highest native-KeyMint-family signal we have, because the device can lie in one
    // channel (attestation blob, framework wrapper, or VINTF) while still exposing a newer backend in
    // another. Using the max avoids downgrading a KeyMint 3 device into the looser KeyMint 1/2 path.
    // 这里取“最高的 KeyMint 家族版本信号”，是为了防止单一信号源被篡改或过旧时，把本应走严格
    // KeyMint 3+ 语义的设备误降级到 KeyMint 1/2 的宽松路径。
    return listOfNotNull(attestationVersion, keymasterVersion, declaredKeyMintVersion)
        .filter { it >= 100 }
        .maxOrNull()
}

private const val KEYMINT_DIGEST_NONE = 0
private const val KEYMINT_VERSION_1 = 100
private const val KEYMINT_DIGEST_SHA_256 = 4
private const val KEYMINT_DIGEST_SHA_224 = 3
private const val KEYMINT_ERROR_INCOMPATIBLE_MGF_DIGEST = -78
private const val KEYMINT_ERROR_UNSUPPORTED_MGF_DIGEST = -79
private const val KEYMINT_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1
private const val KEYMINT_SECURITY_LEVEL_STRONGBOX = 2

private data class RawRsaOaepKey(
    val service: Any,
    val cleanupDescriptor: Any,
    val operationDescriptor: Any,
    val securityLevel: Any,
    val expectedSecurityLevel: Int,
    val returnedSecurityLevel: Int,
    val publicKey: PublicKey,
    val authorizations: List<AuthorizationSummary>,
)

private fun RawRsaOaepKey.operationDiagnostic(operation: String): String = buildString {
    append("serviceClass=")
    append(service.javaClass.name)
    append(", securityLevelClass=")
    append(securityLevel.javaClass.name)
    append(", descriptorClass=")
    append(operationDescriptor.javaClass.name)
    append(", publicKeyAlgorithm=")
    append(publicKey.algorithm)
    append(", ")
    append("selectedSecurityLevel=")
    append(expectedSecurityLevel)
    append(", returnedSecurityLevel=")
    append(returnedSecurityLevel)
    append(", authorizationCount=")
    append(authorizations.size)
    append(", mgfAuthorizations=")
    append(
        authorizations
            .filter { it.tag == KEYMINT_TAG_RSA_OAEP_MGF_DIGEST }
            .joinToString { authorization ->
                "value=${authorization.intValue ?: "null"}," +
                    "securityLevel=${authorization.securityLevel ?: "null"}"
            }
            .ifBlank { "none" },
    )
    append(", ")
    append(operation)
}
