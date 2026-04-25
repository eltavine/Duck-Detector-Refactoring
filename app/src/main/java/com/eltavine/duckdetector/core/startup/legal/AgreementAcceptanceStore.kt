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

package com.eltavine.duckdetector.core.startup.legal

import android.content.Context
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.preferencesDataStoreFile
import java.io.IOException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map

data class AgreementAcceptancePrefs(
    val accepted: Boolean,
)

class AgreementAcceptanceStore private constructor(
    context: Context,
) {
    private val dataStore = PreferenceDataStoreFactory.create(
        produceFile = { context.preferencesDataStoreFile("startup_agreement_prefs") },
    )

    val prefs: Flow<AgreementAcceptancePrefs> = dataStore.data
        .catch { throwable ->
            if (throwable is IOException) {
                emit(emptyPreferences())
            } else {
                throw throwable
            }
        }
        .map { prefs ->
            AgreementAcceptancePrefs(
                accepted = prefs[KEY_ACCEPTED] ?: false,
            )
        }

    suspend fun accept() {
        dataStore.edit { prefs ->
            prefs[KEY_ACCEPTED] = true
        }
    }

    companion object {
        @Volatile
        private var instance: AgreementAcceptanceStore? = null

        private val KEY_ACCEPTED = booleanPreferencesKey("accepted")

        fun getInstance(context: Context): AgreementAcceptanceStore {
            return instance ?: synchronized(this) {
                instance ?: AgreementAcceptanceStore(context.applicationContext).also { created ->
                    instance = created
                }
            }
        }
    }
}
