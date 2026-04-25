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

package com.eltavine.duckdetector.features.tee.data.preferences

import android.content.Context
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStoreFile
import java.io.IOException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map

interface TeeNetworkPrefsStore {
    val prefs: Flow<TeeNetworkPrefs>

    suspend fun setConsent(granted: Boolean)

    suspend fun storeCrlCache(json: String?, fetchedAt: Long)

    suspend fun clearCache()
}

class TeeNetworkConsentStore private constructor(context: Context) : TeeNetworkPrefsStore {

    private val dataStore = PreferenceDataStoreFactory.create(
        produceFile = { context.preferencesDataStoreFile("tee_network_prefs") },
    )

    override val prefs: Flow<TeeNetworkPrefs> = dataStore.data
        .catch { throwable ->
            if (throwable is IOException) {
                emit(emptyPreferences())
            } else {
                throw throwable
            }
        }
        .map { prefs ->
            TeeNetworkPrefs(
                consentAsked = prefs[KEY_CONSENT_ASKED] ?: false,
                consentGranted = prefs[KEY_CONSENT_GRANTED] ?: false,
                crlCacheJson = prefs[KEY_CRL_JSON],
                crlFetchedAt = prefs[KEY_CRL_FETCHED_AT] ?: 0L,
            )
        }

    override suspend fun setConsent(granted: Boolean) {
        dataStore.edit { prefs ->
            prefs[KEY_CONSENT_ASKED] = true
            prefs[KEY_CONSENT_GRANTED] = granted
            prefs.remove(KEY_CRL_JSON)
            prefs.remove(KEY_CRL_FETCHED_AT)
        }
    }

    override suspend fun storeCrlCache(json: String?, fetchedAt: Long) {
        dataStore.edit { prefs ->
            if (json.isNullOrBlank()) {
                prefs.remove(KEY_CRL_JSON)
            } else {
                prefs[KEY_CRL_JSON] = json
            }
            prefs[KEY_CRL_FETCHED_AT] = fetchedAt
        }
    }

    override suspend fun clearCache() {
        dataStore.edit { prefs ->
            prefs.remove(KEY_CRL_JSON)
            prefs.remove(KEY_CRL_FETCHED_AT)
        }
    }

    companion object {
        @Volatile
        private var instance: TeeNetworkConsentStore? = null

        private val KEY_CONSENT_ASKED = booleanPreferencesKey("tee_network_consent_asked")
        private val KEY_CONSENT_GRANTED = booleanPreferencesKey("tee_network_consent_granted")
        private val KEY_CRL_JSON = stringPreferencesKey("tee_crl_cache_json")
        private val KEY_CRL_FETCHED_AT = longPreferencesKey("tee_crl_cache_fetched_at")

        fun getInstance(context: Context): TeeNetworkConsentStore {
            return instance ?: synchronized(this) {
                instance ?: TeeNetworkConsentStore(context.applicationContext).also { created ->
                    instance = created
                }
            }
        }
    }
}

data class TeeNetworkPrefs(
    val consentAsked: Boolean,
    val consentGranted: Boolean,
    val crlCacheJson: String?,
    val crlFetchedAt: Long,
)
