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
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale

class LegacyKeystorePathProbe {

    private val certificateFactory = CertificateFactory.getInstance("X.509")

    fun inspect(): LegacyKeystorePathResult {
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duck_legacy_path_${System.nanoTime()}"
        return runCatching {
            val hookInstalled = KeystoreBinderCaptureHook.installHook()
            if (!hookInstalled) {
                return LegacyKeystorePathResult(
                    executed = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M,
                    hookInstalled = false,
                    detail = "Legacy keystore capture hook bootstrap failed.",
                )
            }
            KeystoreBinderCaptureHook.resetCaptures()
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = "CN=DuckDetector Legacy Path, O=Eltavine",
                useStrongBox = false,
                challenge = "duck_legacy_path".encodeToByteArray(),
            )
            val keystoreChain = AndroidKeyStoreTools.readCertificateChain(keyStore, alias)
            val userCert = KeystoreBinderCaptureHook.getLegacyKeystoreBlob("USRCERT_$alias")
            val caCert = KeystoreBinderCaptureHook.getLegacyKeystoreBlob("CACERT_$alias")
            val legacyChain = buildLegacyFullChain(userCert, caCert)
            val chainMatches = when {
                keystoreChain.isEmpty() || legacyChain.isEmpty() -> false
                else -> chainsEqualDer(keystoreChain.map(X509Certificate::getEncoded), legacyChain)
            }
            LegacyKeystorePathResult(
                executed = true,
                hookInstalled = true,
                userCertCaptured = userCert != null,
                caCertCaptured = caCert != null,
                legacyMaterialAvailable = legacyChain.isNotEmpty(),
                chainMatches = chainMatches,
                legacyChainLength = legacyChain.size,
                detail = buildString {
                    append("userCertCaptured=")
                    append(userCert != null)
                    append(", caCertCaptured=")
                    append(caCert != null)
                    append(", legacyChainLength=")
                    append(legacyChain.size)
                    append(", chainMatches=")
                    append(chainMatches)
                    if (legacyChain.isNotEmpty() && keystoreChain.isNotEmpty() && !chainMatches) {
                        append(", mismatch=")
                        append(describeChainMismatch(keystoreChain.map(X509Certificate::getEncoded), legacyChain))
                    }
                },
            )
        }.getOrElse { throwable ->
            LegacyKeystorePathResult(
                executed = true,
                detail = throwable.message ?: "Legacy keystore path probe failed.",
            )
        }.also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
            KeystoreBinderCaptureHook.restore()
        }
    }

    private fun buildLegacyFullChain(userCert: ByteArray?, caCert: ByteArray?): List<ByteArray> {
        val out = mutableListOf<ByteArray>()
        if (userCert != null) {
            out += userCert
        } else if (caCert != null) {
            out += caCert
        }
        if (caCert != null && caCert.isNotEmpty()) {
            runCatching {
                val certificates = certificateFactory.generateCertificates(ByteArrayInputStream(caCert))
                certificates.filterIsInstance<X509Certificate>().forEach { certificate ->
                    val encoded = certificate.encoded
                    if (out.none { it.contentEquals(encoded) }) {
                        out += encoded
                    }
                }
            }
        }
        return out
    }

    private fun chainsEqualDer(left: List<ByteArray>, right: List<ByteArray>): Boolean {
        return left.size == right.size && left.zip(right).all { (a, b) -> a.contentEquals(b) }
    }

    private fun describeChainMismatch(keystoreChain: List<ByteArray>, legacyChain: List<ByteArray>): String {
        val min = minOf(keystoreChain.size, legacyChain.size)
        for (index in 0 until min) {
            if (!keystoreChain[index].contentEquals(legacyChain[index])) {
                return "mismatchIndex=$index keystoreSerial=${tryGetSerialHex(keystoreChain[index])} legacySerial=${tryGetSerialHex(legacyChain[index])}"
            }
        }
        return if (keystoreChain.size != legacyChain.size) {
            "lengthMismatch keystore=${keystoreChain.size} legacy=${legacyChain.size}"
        } else {
            "unknown"
        }
    }

    private fun tryGetSerialHex(certDer: ByteArray): String {
        return runCatching {
            val certificate = certificateFactory.generateCertificate(ByteArrayInputStream(certDer)) as X509Certificate
            certificate.serialNumber.toString(16).lowercase(Locale.US)
        }.getOrDefault("parse_failed")
    }
}

data class LegacyKeystorePathResult(
    val executed: Boolean,
    val hookInstalled: Boolean = false,
    val userCertCaptured: Boolean = false,
    val caCertCaptured: Boolean = false,
    val legacyMaterialAvailable: Boolean = false,
    val chainMatches: Boolean = false,
    val legacyChainLength: Int = 0,
    val detail: String,
)
