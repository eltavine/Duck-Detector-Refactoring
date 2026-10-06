/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.startup

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

data class StartupPolicyReviewPrefs(
    val completed: Boolean,
)

/**
 * Persists whether the initial startup policy review has been completed.
 *
 * The startup policy screen itself can still appear on later launches while runtime state is being
 * resolved. This flag only distinguishes first-run-only content, such as the UI style selector,
 * from policy/loading content that remains useful on subsequent launches.
 */
class StartupPolicyReviewStore private constructor(
    context: Context,
) {
    private val dataStore = PreferenceDataStoreFactory.create(
        produceFile = { context.preferencesDataStoreFile("startup_policy_review_prefs") },
    )

    val prefs: Flow<StartupPolicyReviewPrefs> = dataStore.data
        .catch { throwable ->
            if (throwable is IOException) {
                emit(emptyPreferences())
            } else {
                throw throwable
            }
        }
        .map { prefs ->
            StartupPolicyReviewPrefs(
                completed = prefs[KEY_COMPLETED] ?: false,
            )
        }

    suspend fun complete() {
        dataStore.edit { prefs ->
            prefs[KEY_COMPLETED] = true
        }
    }

    companion object {
        @Volatile
        private var instance: StartupPolicyReviewStore? = null

        private val KEY_COMPLETED = booleanPreferencesKey("completed")

        fun getInstance(context: Context): StartupPolicyReviewStore {
            return instance ?: synchronized(this) {
                instance ?: StartupPolicyReviewStore(context.applicationContext).also { created ->
                    instance = created
                }
            }
        }
    }
}
