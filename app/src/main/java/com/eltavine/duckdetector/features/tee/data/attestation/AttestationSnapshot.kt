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

package com.eltavine.duckdetector.features.tee.data.attestation

import com.eltavine.duckdetector.features.tee.domain.TeeCertificateItem
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import java.security.cert.X509Certificate

data class AttestationSnapshot(
    val tier: TeeTier,
    val attestationVersion: Int?,
    val keymasterVersion: Int?,
    val attestationTier: TeeTier?,
    val keymasterTier: TeeTier?,
    val challengeVerified: Boolean,
    val challengeSummary: String?,
    val rootOfTrust: RootOfTrustSnapshot?,
    val osVersion: String?,
    val osPatchLevel: String?,
    val vendorPatchLevel: String?,
    val bootPatchLevel: String?,
    val keyProperties: AttestedKeyProperties = AttestedKeyProperties(),
    val authState: AttestedAuthState = AttestedAuthState(),
    val applicationInfo: AttestedApplicationInfo = AttestedApplicationInfo(),
    val deviceInfo: AttestedDeviceInfo = AttestedDeviceInfo(),
    val deviceUniqueAttestation: Boolean = false,
    val trustedAttestationIndex: Int? = null,
    val rawCertificates: List<X509Certificate>,
    val displayCertificates: List<TeeCertificateItem>,
    val errorMessage: String? = null,
)

data class RootOfTrustSnapshot(
    val verifiedBootKeyHex: String?,
    val deviceLocked: Boolean?,
    val verifiedBootState: String?,
    val verifiedBootHashHex: String?,
)

data class AttestedKeyProperties(
    val algorithm: String? = null,
    val keySize: Int? = null,
    val ecCurve: String? = null,
    val purposes: List<String> = emptyList(),
    val digests: List<String> = emptyList(),
    val paddings: List<String> = emptyList(),
    val origin: String? = null,
    val rollbackResistant: Boolean = false,
)

data class AttestedAuthState(
    val noAuthRequired: Boolean? = null,
    val userAuthTypes: List<String> = emptyList(),
    val authTimeoutSeconds: Int? = null,
    val trustedConfirmationRequired: Boolean = false,
    val trustedPresenceRequired: Boolean = false,
    val unlockedDeviceRequired: Boolean = false,
)

data class AttestedApplicationInfo(
    val packageNames: List<String> = emptyList(),
    val signatureDigestsSha256: List<String> = emptyList(),
    val rawBytesHex: String? = null,
)

data class AttestedDeviceInfo(
    val brand: String? = null,
    val device: String? = null,
    val product: String? = null,
    val manufacturer: String? = null,
    val model: String? = null,
    val serial: String? = null,
    val imei: String? = null,
    val secondImei: String? = null,
    val meid: String? = null,
) {
    fun asDisplayMap(): Map<String, String> = buildMap {
        brand?.let { put("Brand", it) }
        device?.let { put("Device", it) }
        product?.let { put("Product", it) }
        manufacturer?.let { put("Manufacturer", it) }
        model?.let { put("Model", it) }
        serial?.let { put("Serial", it) }
        imei?.let { put("IMEI", it) }
        secondImei?.let { put("Second IMEI", it) }
        meid?.let { put("MEID", it) }
    }
}
