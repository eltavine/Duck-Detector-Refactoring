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
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore

class UpdateSubcomponentProbe {

    fun inspect(useStrongBox: Boolean = false): UpdateSubcomponentResult {
        val alias = "duck_update_sub_${System.nanoTime()}"
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return runCatching {
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            ).setDigests(KeyProperties.DIGEST_SHA256)
            if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(true)
            }
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore",
            )
            generator.initialize(builder.build())
            generator.generateKeyPair()
            val key = keyStore.getKey(alias, null)
            val chain = keyStore.getCertificateChain(alias)
            if (key == null || chain.isNullOrEmpty()) {
                return UpdateSubcomponentResult(
                    updateSucceeded = false,
                    keyNotFoundStyleFailure = false,
                    detail = "Generated key but could not read key material back for update probe.",
                )
            }
            try {
                keyStore.setKeyEntry(alias, key, null, chain)
                UpdateSubcomponentResult(
                    updateSucceeded = true,
                    keyNotFoundStyleFailure = false,
                    detail = "setKeyEntry completed without an updateSubcomponent anomaly.",
                )
            } catch (throwable: Throwable) {
                val message = throwable.message.orEmpty()
                val keyNotFound = KEY_NOT_FOUND_PATTERNS.any { pattern ->
                    message.contains(pattern, ignoreCase = true)
                }
                UpdateSubcomponentResult(
                    updateSucceeded = false,
                    keyNotFoundStyleFailure = keyNotFound,
                    detail = message.ifBlank { "setKeyEntry failed during update probe." },
                )
            }
        }.getOrElse { throwable ->
            UpdateSubcomponentResult(
                updateSucceeded = false,
                keyNotFoundStyleFailure = false,
                detail = throwable.message ?: "Update subcomponent probe failed.",
            )
        }.also {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    companion object {
        private val KEY_NOT_FOUND_PATTERNS = listOf(
            "key not found",
            "KEY_NOT_FOUND",
            "error 7",
            "No key to update",
        )
    }
}

data class UpdateSubcomponentResult(
    val updateSucceeded: Boolean,
    val keyNotFoundStyleFailure: Boolean,
    val detail: String,
)
