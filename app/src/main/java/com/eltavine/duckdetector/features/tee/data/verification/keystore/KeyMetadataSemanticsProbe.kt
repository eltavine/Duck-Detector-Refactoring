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

class KeyMetadataSemanticsProbe(
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
) {

    fun inspect(): KeyMetadataSemanticsResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return KeyMetadataSemanticsResult(
                executed = false,
                detail = "KeyMetadata semantics probe requires Android 12 or newer.",
            )
        }
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duck_metadata_semantics_${System.nanoTime()}"
        return runCatching {
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = "CN=DuckDetector Metadata Semantics, O=Eltavine",
                useStrongBox = false,
            )
            val service = binderClient.getKeystoreService()
                ?: return KeyMetadataSemanticsResult(
                    executed = false,
                    detail = "Keystore2 service interface was unavailable.",
                )
            val response = binderClient.getKeyEntryResponse(service, binderClient.createKeyDescriptor(alias))
                ?: return KeyMetadataSemanticsResult(
                    executed = true,
                    detail = "Keystore2 getKeyEntry() returned null for the probe alias.",
                )
            val descriptor = binderClient.getReturnedDescriptor(response)
                ?: return KeyMetadataSemanticsResult(
                    executed = true,
                    detail = "KeyMetadata did not expose a returned key descriptor.",
                )
            val domain = binderClient.getDescriptorDomain(descriptor)
            val returnedAlias = binderClient.getDescriptorAlias(descriptor)
            val namespace = binderClient.getDescriptorNamespace(descriptor)
            KeyMetadataSemanticsResult(
                executed = true,
                usesKeyIdDomain = domain == binderClient.getDomainKeyId(),
                aliasCleared = returnedAlias == null,
                namespace = namespace,
                detail = "domain=${domain ?: "unknown"}, alias=${returnedAlias ?: "null"}, nspace=${namespace ?: "unknown"}",
            )
        }.getOrElse { throwable ->
            KeyMetadataSemanticsResult(
                executed = false,
                detail = throwable.message ?: "KeyMetadata semantics probe could not complete.",
            )
        }.also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }
}

data class KeyMetadataSemanticsResult(
    val executed: Boolean,
    val usesKeyIdDomain: Boolean = false,
    val aliasCleared: Boolean = false,
    val namespace: Long? = null,
    val detail: String,
)
