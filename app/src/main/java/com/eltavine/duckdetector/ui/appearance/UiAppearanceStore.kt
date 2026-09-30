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

package com.eltavine.duckdetector.ui.appearance

import android.content.Context
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStoreFile
import io.github.xiaotong6666.uihelper.mode.UiMode
import java.io.IOException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map

/** UI-only preference; detector sessions and the headless SDK never observe the selected skin. */
internal class UiAppearanceStore private constructor(context: Context) {
    private val dataStore = PreferenceDataStoreFactory.create(
        produceFile = { context.preferencesDataStoreFile("duck_ui_appearance") },
    )

    val mode: Flow<UiMode> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { preferences -> UiMode.fromValue(preferences[KEY_UI_MODE] ?: UiMode.Miuix.value) }

    suspend fun setMode(mode: UiMode) {
        dataStore.edit { it[KEY_UI_MODE] = mode.value }
    }

    companion object {
        private val KEY_UI_MODE = stringPreferencesKey("ui_mode")

        @Volatile
        private var instance: UiAppearanceStore? = null

        fun getInstance(context: Context): UiAppearanceStore = instance ?: synchronized(this) {
            instance ?: UiAppearanceStore(context.applicationContext).also { instance = it }
        }
    }
}
