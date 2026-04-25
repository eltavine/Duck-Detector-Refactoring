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

import android.content.Context
import android.os.Build
import android.security.keystore.KeyProtection
import android.security.keystore.KeyProperties
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

class KeyboxImportProbe(
    private val context: Context,
) {

    fun inspect(
        keyStore: KeyStore = AndroidKeyStoreTools.loadKeyStore(),
    ): KeyboxImportResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return KeyboxImportResult(
                executed = false,
                markerPreserved = true,
                marker = FIXTURE_MARKER,
                detail = "Keybox import probe requires Android 12 or newer.",
            )
        }
        val alias = "duck_keybox_probe_${System.nanoTime()}"
        if (!AndroidKeyStoreTools.generateAttestOnlyEcKey(keyStore, alias)) {
            return KeyboxImportResult(
                executed = false,
                markerPreserved = true,
                marker = FIXTURE_MARKER,
                detail = "PURPOSE_ATTEST_KEY could not be provisioned for the probe alias.",
            )
        }
        return runCatching {
            val fixture = KeyboxFixtureLoader(context).load()
            val protection = KeyProtection.Builder(KeyProperties.PURPOSE_ATTEST_KEY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
            keyStore.setEntry(
                alias,
                KeyStore.PrivateKeyEntry(fixture.privateKey, arrayOf(fixture.certificate)),
                protection,
            )
            val retrieved = keyStore.getCertificate(alias) as? X509Certificate
            if (retrieved == null) {
                return KeyboxImportResult(
                    executed = false,
                    markerPreserved = true,
                    marker = FIXTURE_MARKER,
                    detail = "Probe alias returned no certificate after setEntry().",
                )
            }
            val subject = retrieved.subjectX500Principal.name
            val preserved = subject.contains(FIXTURE_MARKER)
            KeyboxImportResult(
                executed = true,
                markerPreserved = preserved,
                marker = FIXTURE_MARKER,
                detail = if (preserved) {
                    "Imported marker certificate returned with its custom subject intact."
                } else {
                    "Imported marker certificate came back with a replaced subject: $subject"
                },
            )
        }.getOrElse { throwable ->
            KeyboxImportResult(
                executed = false,
                markerPreserved = true,
                marker = FIXTURE_MARKER,
                detail = throwable.message ?: "Keybox import probe failed.",
            )
        }.also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }

    private class KeyboxFixtureLoader(
        private val context: Context,
    ) {
        private val certificateFactory = CertificateFactory.getInstance("X.509")

        fun load(): KeyboxFixture {
            val certificatePem = context.resources.openRawResource(R.raw.eltavine_marker_cert)
                .bufferedReader()
                .use { it.readText() }
            val keyPem = context.resources.openRawResource(R.raw.eltavine_marker_key)
                .bufferedReader()
                .use { it.readText() }
            val cert =
                certificateFactory.generateCertificate(certificatePem.byteInputStream()) as X509Certificate
            val key = decodeEcPrivateKey(keyPem)
            return KeyboxFixture(privateKey = key, certificate = cert)
        }

        private fun decodeEcPrivateKey(pem: String): PrivateKey {
            val body = pem.lineSequence()
                .filterNot { it.startsWith("-----") }
                .joinToString(separator = "")
            val bytes = Base64.getDecoder().decode(body)
            return KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(bytes))
        }
    }

    private data class KeyboxFixture(
        val privateKey: PrivateKey,
        val certificate: X509Certificate,
    )

    companion object {
        const val FIXTURE_MARKER = "EltavineMarker-Keybox"
    }
}

data class KeyboxImportResult(
    val executed: Boolean,
    val markerPreserved: Boolean,
    val marker: String,
    val detail: String,
)
