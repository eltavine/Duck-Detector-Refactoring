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

package com.eltavine.duckdetector.core.notifications.preferences

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

interface ScanNotificationPrefsStore {
    val prefs: Flow<ScanNotificationPrefs>

    suspend fun markNotificationsPrompted()

    suspend fun markLiveUpdatesPrompted()
}

class ScanNotificationConsentStore private constructor(
    context: Context,
) : ScanNotificationPrefsStore {

    private val dataStore = PreferenceDataStoreFactory.create(
        produceFile = { context.preferencesDataStoreFile("scan_notification_prefs") },
    )

    override val prefs: Flow<ScanNotificationPrefs> = dataStore.data
        .catch { throwable ->
            if (throwable is IOException) {
                emit(emptyPreferences())
            } else {
                throw throwable
            }
        }
        .map { prefs ->
            ScanNotificationPrefs(
                notificationsPrompted = prefs[KEY_NOTIFICATIONS_PROMPTED] ?: false,
                liveUpdatesPrompted = prefs[KEY_LIVE_UPDATES_PROMPTED] ?: false,
            )
        }

    override suspend fun markNotificationsPrompted() {
        dataStore.edit { prefs ->
            prefs[KEY_NOTIFICATIONS_PROMPTED] = true
        }
    }

    override suspend fun markLiveUpdatesPrompted() {
        dataStore.edit { prefs ->
            prefs[KEY_LIVE_UPDATES_PROMPTED] = true
        }
    }

    companion object {
        @Volatile
        private var instance: ScanNotificationConsentStore? = null

        private val KEY_NOTIFICATIONS_PROMPTED =
            booleanPreferencesKey("scan_notifications_prompted")
        private val KEY_LIVE_UPDATES_PROMPTED =
            booleanPreferencesKey("scan_live_updates_prompted")

        fun getInstance(context: Context): ScanNotificationConsentStore {
            return instance ?: synchronized(this) {
                instance
                    ?: ScanNotificationConsentStore(context.applicationContext).also { created ->
                        instance = created
                    }
            }
        }
    }
}

data class ScanNotificationPrefs(
    val notificationsPrompted: Boolean,
    val liveUpdatesPrompted: Boolean,
)
