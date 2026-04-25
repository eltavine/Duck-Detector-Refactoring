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

class KeyMetadataShapeProbe(
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
) {

    fun inspect(): KeyMetadataShapeResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return KeyMetadataShapeResult(
                executed = false,
                detail = "KeyMetadata shape probe requires Android 12 or newer.",
            )
        }
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duck_metadata_shape_${System.nanoTime()}"
        return runCatching {
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = "CN=DuckDetector Metadata Shape, O=Eltavine",
                useStrongBox = false,
            )
            val service = binderClient.getKeystoreService()
                ?: return KeyMetadataShapeResult(
                    executed = false,
                    detail = "Keystore2 service interface was unavailable.",
                )
            val response = binderClient.getKeyEntryResponse(service, binderClient.createKeyDescriptor(alias))
                ?: return KeyMetadataShapeResult(
                    executed = true,
                    detail = "Keystore2 getKeyEntry() returned null for the probe alias.",
                )
            val metadata = binderClient.getMetadata(response)
                ?: return KeyMetadataShapeResult(
                    executed = true,
                    detail = "Keystore2 response did not contain metadata.",
                )
            val originTag = binderClient.getTagValue("ORIGIN")
            val tags = binderClient.getMetadataAuthorizations(metadata).mapNotNull { authorization ->
                authorization?.let(binderClient::getAuthorizationTag)
            }
            val hasOrigin = originTag != null && tags.contains(originTag)
            val modificationTimeMs = binderClient.getMetadataModificationTimeMs(metadata)
            KeyMetadataShapeResult(
                executed = true,
                modificationTimeValid = modificationTimeMs?.let { it > 0L } == true,
                hasOriginTag = hasOrigin,
                authorizationCount = tags.size,
                detail = "modificationTimeMs=${modificationTimeMs ?: "unknown"}, authCount=${tags.size}, hasOrigin=$hasOrigin",
            )
        }.getOrElse { throwable ->
            KeyMetadataShapeResult(
                executed = false,
                detail = throwable.message ?: "KeyMetadata shape probe could not complete.",
            )
        }.also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }
}

data class KeyMetadataShapeResult(
    val executed: Boolean,
    val modificationTimeValid: Boolean = false,
    val hasOriginTag: Boolean = false,
    val authorizationCount: Int = 0,
    val detail: String,
)
