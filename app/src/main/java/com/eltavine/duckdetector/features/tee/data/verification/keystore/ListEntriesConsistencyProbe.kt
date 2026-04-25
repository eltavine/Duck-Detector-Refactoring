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

import android.os.BadParcelableException
import android.os.Build
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.security.KeyStore

class ListEntriesConsistencyProbe {

    fun inspect(): ListEntriesConsistencyResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return ListEntriesConsistencyResult(
                executed = false,
                detail = "listEntries consistency probe requires Android 12 or newer.",
            )
        }
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duck_list_entries_${System.nanoTime()}"
        return try {
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = "CN=DuckDetector ListEntries, O=Eltavine",
                useStrongBox = false,
            )
            val containsAlias = keyStore.containsAlias(alias)
            val aliases = buildList {
                val enumeration = keyStore.aliases()
                while (enumeration.hasMoreElements()) {
                    add(enumeration.nextElement())
                }
            }
            val listedInAliases = aliases.contains(alias)
            ListEntriesConsistencyResult(
                executed = true,
                containsAlias = containsAlias,
                listedInAliases = listedInAliases,
                inconsistent = containsAlias != listedInAliases,
                detail = "containsAlias=$containsAlias, listedInAliases=$listedInAliases, aliasCount=${aliases.size}",
            )
        } catch (throwable: Throwable) {
            val badParcelableLikeCrash = isBadParcelableLikeCrash(throwable)
            ListEntriesConsistencyResult(
                executed = badParcelableLikeCrash,
                badParcelableLikeCrash = badParcelableLikeCrash,
                inconsistent = badParcelableLikeCrash,
                detail = if (badParcelableLikeCrash) {
                    "aliases() crashed with a BadParcelable-style failure: ${throwable.message ?: throwable.javaClass.simpleName}"
                } else {
                    throwable.message ?: "listEntries consistency probe could not complete."
                },
            )
        }.also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }

    private fun isBadParcelableLikeCrash(throwable: Throwable): Boolean {
        var current: Throwable? = throwable
        while (current != null) {
            val message = current.message.orEmpty()
            if (current is BadParcelableException ||
                message.contains("BadParcelableException") ||
                message.contains("Parcelable too small") ||
                message.contains("KeyDescriptor.readFromParcel")
            ) {
                return true
            }
            current = current.cause
        }
        return false
    }
}

data class ListEntriesConsistencyResult(
    val executed: Boolean,
    val containsAlias: Boolean? = null,
    val listedInAliases: Boolean? = null,
    val badParcelableLikeCrash: Boolean = false,
    val inconsistent: Boolean = false,
    val detail: String,
)
