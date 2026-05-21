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
import com.eltavine.duckdetector.R
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

internal class KeyboxFixtureLoader(
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

internal data class KeyboxFixture(
    val privateKey: PrivateKey,
    val certificate: X509Certificate,
)
