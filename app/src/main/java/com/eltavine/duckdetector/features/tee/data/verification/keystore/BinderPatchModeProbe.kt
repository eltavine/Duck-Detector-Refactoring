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

class BinderPatchModeProbe(
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
) {

    private val certificateFactory = CertificateFactory.getInstance("X.509")

    fun inspect(): BinderPatchModeResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return BinderPatchModeResult(
                executed = false,
                detail = "Binder patch-mode probe requires Android 12 or newer.",
            )
        }
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duck_patch_mode_${System.nanoTime()}"
        return runCatching {
            val hookInstalled = KeystoreBinderCaptureHook.installHook()
            if (!hookInstalled) {
                return BinderPatchModeResult(
                    executed = true,
                    hookInstalled = false,
                    detail = "Binder capture hook bootstrap failed before patch-mode probe.",
                )
            }
            KeystoreBinderCaptureHook.resetCaptures()
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = "CN=DuckDetector Patch Mode, O=Eltavine",
                useStrongBox = false,
                challenge = "duck_patch_mode".encodeToByteArray(),
            )
            val service = binderClient.getKeystoreService()
                ?: return BinderPatchModeResult(
                    executed = true,
                    hookInstalled = true,
                    detail = "Keystore2 service interface was unavailable.",
                )
            binderClient.getKeyEntryResponse(service, binderClient.createKeyDescriptor(alias))

            val generateLeaf = KeystoreBinderCaptureHook.getGenerateKeyLeafCertificate(alias)
            val generateChainBlob = KeystoreBinderCaptureHook.getGenerateKeyCertificateChainBlob(alias)
            val keyEntryLeaf = KeystoreBinderCaptureHook.getKeyEntryLeafCertificate(alias)
            val keyEntryChainBlob = KeystoreBinderCaptureHook.getKeyEntryCertificateChainBlob(alias)
            val generateChain = buildFullChain(generateLeaf, generateChainBlob)
            val keyEntryChain = buildFullChain(keyEntryLeaf, keyEntryChainBlob)

            val leafDiffers = when {
                generateLeaf == null || keyEntryLeaf == null -> false
                else -> !generateLeaf.contentEquals(keyEntryLeaf)
            }
            val chainDiffers = when {
                generateChain.isEmpty() || keyEntryChain.isEmpty() -> false
                else -> !chainsEqualDer(generateChain, keyEntryChain)
            }

            BinderPatchModeResult(
                executed = true,
                hookInstalled = true,
                generateMaterialAvailable = generateChain.isNotEmpty(),
                keyEntryMaterialAvailable = keyEntryChain.isNotEmpty(),
                leafDiffers = leafDiffers,
                chainDiffers = chainDiffers,
                detail = "leafDiffers=$leafDiffers, chainDiffers=$chainDiffers, generateChainLength=${generateChain.size}, keyEntryChainLength=${keyEntryChain.size}",
            )
        }.getOrElse { throwable ->
            BinderPatchModeResult(
                executed = true,
                detail = throwable.message ?: "Binder patch-mode probe failed.",
            )
        }.also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
            KeystoreBinderCaptureHook.restore()
        }
    }

    private fun buildFullChain(leafDer: ByteArray?, chainBlob: ByteArray?): List<ByteArray> {
        val out = mutableListOf<ByteArray>()
        if (leafDer == null) {
            return out
        }
        out += leafDer
        if (chainBlob == null || chainBlob.isEmpty()) {
            return out
        }
        runCatching {
            val certificates = certificateFactory.generateCertificates(ByteArrayInputStream(chainBlob))
            certificates.filterIsInstance<X509Certificate>().forEach { certificate ->
                val encoded = certificate.encoded
                if (out.none { it.contentEquals(encoded) }) {
                    out += encoded
                }
            }
        }
        return out
    }

    private fun chainsEqualDer(left: List<ByteArray>, right: List<ByteArray>): Boolean {
        return left.size == right.size && left.zip(right).all { (a, b) -> a.contentEquals(b) }
    }
}

data class BinderPatchModeResult(
    val executed: Boolean,
    val hookInstalled: Boolean = false,
    val generateMaterialAvailable: Boolean = false,
    val keyEntryMaterialAvailable: Boolean = false,
    val leafDiffers: Boolean = false,
    val chainDiffers: Boolean = false,
    val detail: String,
)
