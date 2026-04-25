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

class ListEntriesBatchedProbe(
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
) {

    fun inspect(): ListEntriesBatchedResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            return ListEntriesBatchedResult(
                executed = false,
                detail = "listEntriesBatched probe requires Android 14 or newer.",
            )
        }
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val aliasPrefix = "zzzz_duck_${System.nanoTime()}"
        val alias0 = "${aliasPrefix}_0"
        val alias1 = "${aliasPrefix}_1"
        return runCatching {
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias0,
                subject = "CN=DuckDetector ListEntriesBatched 0, O=Eltavine",
                useStrongBox = false,
            )
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias1,
                subject = "CN=DuckDetector ListEntriesBatched 1, O=Eltavine",
                useStrongBox = false,
            )
            val service = binderClient.getKeystoreService()
                ?: return ListEntriesBatchedResult(
                    executed = false,
                    detail = "Keystore2 service interface was unavailable.",
                )
            val aliases = binderClient.listEntriesBatched(service, alias0)
                .mapNotNull { descriptor -> descriptor?.let(binderClient::getDescriptorAlias) }
            val cursorEchoed = aliases.contains(alias0)
            val expectedNextMissing = !aliases.contains(alias1)
            ListEntriesBatchedResult(
                executed = true,
                cursorEchoed = cursorEchoed,
                expectedNextMissing = expectedNextMissing,
                aliases = aliases,
                detail = "cursorEchoed=$cursorEchoed, expectedNextMissing=$expectedNextMissing, aliasCount=${aliases.size}",
            )
        }.getOrElse { throwable ->
            ListEntriesBatchedResult(
                executed = false,
                detail = "listEntriesBatched probe could not complete: ${binderClient.describeThrowable(throwable)}",
            )
        }.also {
            AndroidKeyStoreTools.cleanup(keyStore, listOf(alias0, alias1))
        }
    }
}

data class ListEntriesBatchedResult(
    val executed: Boolean,
    val cursorEchoed: Boolean = false,
    val expectedNextMissing: Boolean = false,
    val aliases: List<String> = emptyList(),
    val detail: String,
)
