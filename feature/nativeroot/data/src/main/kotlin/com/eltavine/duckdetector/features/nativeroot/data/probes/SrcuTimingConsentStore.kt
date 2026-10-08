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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import android.content.Context
import com.eltavine.duckdetector.core.detector.ConsentDecision
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged

/** Only the host process reads this preference; the carrier receives no persistent permissions. */
class SrcuTimingConsentStore(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("srcu_timing", Context.MODE_PRIVATE)
    fun decision(): ConsentDecision = when {
        !prefs.contains("enabled") -> ConsentDecision.UNDECIDED
        prefs.getBoolean("enabled", false) -> ConsentDecision.GRANTED
        else -> ConsentDecision.DECLINED
    }
    val decisions: Flow<ConsentDecision> get() = callbackFlow {
        val listener = android.content.SharedPreferences.OnSharedPreferenceChangeListener { _, _ ->
            trySend(decision())
        }
        prefs.registerOnSharedPreferenceChangeListener(listener)
        trySend(decision())
        awaitClose { prefs.unregisterOnSharedPreferenceChangeListener(listener) }
    }.distinctUntilChanged()
    fun decide(granted: Boolean) {
        check(prefs.edit().putBoolean("enabled", granted).commit()) { "Could not save experiment choice" }
    }
}
