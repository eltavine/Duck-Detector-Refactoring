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

import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.security.KeyStore

class KeyLifecycleProbe {

    fun inspect(
        keyStore: KeyStore = AndroidKeyStoreTools.loadKeyStore(),
        useStrongBox: Boolean = false,
    ): KeyLifecycleResult {
        val alias = "duck_lifecycle_${System.nanoTime()}"
        return runCatching {
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = "CN=DuckDetector Lifecycle Probe, O=Eltavine",
                useStrongBox = useStrongBox,
            )
            val firstSerial = AndroidKeyStoreTools.readLeafCertificate(
                keyStore,
                alias
            )?.serialNumber?.toString(16)
            val created = keyStore.containsAlias(alias)
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
            val deleted = !keyStore.containsAlias(alias)
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = "CN=DuckDetector Lifecycle Probe, O=Eltavine",
                useStrongBox = useStrongBox,
            )
            val secondSerial = AndroidKeyStoreTools.readLeafCertificate(
                keyStore,
                alias
            )?.serialNumber?.toString(16)
            KeyLifecycleResult(
                created = created,
                deleteRemovedAlias = deleted,
                regeneratedFreshMaterial = firstSerial != null && secondSerial != null && firstSerial != secondSerial,
                detail = buildString {
                    append("Create=")
                    append(created)
                    append(", delete=")
                    append(deleted)
                    append(", regenerateFresh=")
                    append(firstSerial != null && secondSerial != null && firstSerial != secondSerial)
                },
            )
        }.getOrElse { throwable ->
            KeyLifecycleResult(
                created = false,
                deleteRemovedAlias = false,
                regeneratedFreshMaterial = false,
                detail = throwable.message ?: "Key lifecycle probe failed.",
            )
        }.also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }
}

data class KeyLifecycleResult(
    val created: Boolean,
    val deleteRemovedAlias: Boolean,
    val regeneratedFreshMaterial: Boolean,
    val detail: String,
)
