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

package com.eltavine.duckdetector.features.locationrisk.data.preferences

import android.content.Context
import com.eltavine.duckdetector.core.detector.ConsentDecision
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.withContext

/** SharedPreferences owns persistence; each flow owns and unregisters its listener. */
class LocationCacheConsentStore(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences("location_risk_consent", Context.MODE_PRIVATE)
    fun decision(): ConsentDecision = when {
        !preferences.getBoolean("asked", false) -> ConsentDecision.UNDECIDED
        preferences.getBoolean("enabled", false) -> ConsentDecision.GRANTED
        else -> ConsentDecision.DECLINED
    }
    fun decisions() = callbackFlow {
        val listener = android.content.SharedPreferences.OnSharedPreferenceChangeListener { _, _ -> trySend(decision()) }
        preferences.registerOnSharedPreferenceChangeListener(listener)
        trySend(decision())
        awaitClose { preferences.unregisterOnSharedPreferenceChangeListener(listener) }
    }.distinctUntilChanged()

    suspend fun decide(granted: Boolean) = withContext(Dispatchers.IO) {
        check(preferences.edit().putBoolean("asked", true).putBoolean("enabled", granted).commit()) {
            "Could not persist location cache consent"
        }
    }
}
