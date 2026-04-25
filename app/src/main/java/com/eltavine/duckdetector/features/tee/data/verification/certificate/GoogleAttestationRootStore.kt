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

package com.eltavine.duckdetector.features.tee.data.verification.certificate

import android.content.Context
import com.eltavine.duckdetector.R
import org.json.JSONArray
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.nio.charset.StandardCharsets

class GoogleAttestationRootStore(
    context: Context,
) {

    private val appContext = context.applicationContext
    private val certificateFactory = CertificateFactory.getInstance("X.509")

    val certificates: List<X509Certificate> by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        val payload = appContext.resources.openRawResource(R.raw.google_attestation_roots)
            .use { stream ->
                stream.reader(StandardCharsets.UTF_8).readText()
            }
        val roots = JSONArray(payload)
        buildList(roots.length()) {
            for (index in 0 until roots.length()) {
                add(parseCertificate(roots.getString(index)))
            }
        }
    }

    val publicKeyFingerprints: Set<String> by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        certificates.mapTo(linkedSetOf()) { cert ->
            cert.publicKey.encoded.sha256()
        }
    }

    fun contains(cert: X509Certificate): Boolean {
        val fingerprint = cert.publicKey.encoded.sha256()
        if (fingerprint in publicKeyFingerprints) {
            return true
        }
        return certificates.any { root ->
            root.encoded.contentEquals(cert.encoded)
        }
    }

    private fun parseCertificate(pem: String): X509Certificate {
        return ByteArrayInputStream(pem.toByteArray(StandardCharsets.UTF_8)).use { stream ->
            certificateFactory.generateCertificate(stream) as X509Certificate
        }
    }

    private fun ByteArray.sha256(): String {
        return MessageDigest.getInstance("SHA-256")
            .digest(this)
            .joinToString(separator = "") { byte -> "%02x".format(byte) }
    }
}
