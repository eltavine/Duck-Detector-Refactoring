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

package com.eltavine.duckdetector.features.update.data

import android.content.Context
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStoreFile
import com.eltavine.duckdetector.features.update.domain.UpdateChannel
import java.io.IOException
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first

/** Stores the channel only once the user picks one, so an unpicked channel keeps following the build. */
internal class UpdateChannelStore private constructor(context: Context) {

    private val dataStore = PreferenceDataStoreFactory.create(
        produceFile = { context.preferencesDataStoreFile("update_channel_prefs") },
    )

    suspend fun read(): UpdateChannel? {
        val prefs = dataStore.data
            .catch { throwable ->
                if (throwable is IOException) {
                    emit(emptyPreferences())
                } else {
                    throw throwable
                }
            }
            .first()
        return prefs[KEY_CHANNEL]?.let(UpdateChannel::fromId)
    }

    suspend fun write(channel: UpdateChannel) {
        dataStore.edit { prefs ->
            prefs[KEY_CHANNEL] = channel.id
        }
    }

    companion object {
        @Volatile
        private var instance: UpdateChannelStore? = null

        private val KEY_CHANNEL = stringPreferencesKey("channel")

        fun getInstance(context: Context): UpdateChannelStore {
            return instance ?: synchronized(this) {
                instance ?: UpdateChannelStore(context.applicationContext).also { created ->
                    instance = created
                }
            }
        }
    }
}
