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

package com.eltavine.duckdetector.features.rootmanagers.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.ConsentDecision
import com.eltavine.duckdetector.core.detector.ConsentId
import com.eltavine.duckdetector.core.detector.DetectorConsent
import com.eltavine.duckdetector.features.rootmanagers.data.probes.canary.InstallerCanaryConsentStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.Flow

/** Optional active diagnostic, disabled until the host records an explicit choice. */
public object RootManagersInstallerCanaryConsent : DetectorConsent {
    override val id: ConsentId = ConsentId("installer_permission_canary")
    override fun decisions(context: Context): Flow<ConsentDecision> =
        InstallerCanaryConsentStore(context).decisions
    override suspend fun decide(context: Context, granted: Boolean): Unit = withContext(Dispatchers.IO) {
        InstallerCanaryConsentStore(context).decide(granted)
    }
}
