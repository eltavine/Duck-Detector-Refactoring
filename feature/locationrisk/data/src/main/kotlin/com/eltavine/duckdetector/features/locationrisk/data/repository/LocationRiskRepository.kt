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

package com.eltavine.duckdetector.features.locationrisk.data.repository

import android.content.Context
import com.eltavine.duckdetector.capability.packageinventory.data.AndroidInstalledPackageInventoryReader
import com.eltavine.duckdetector.core.detector.ConsentDecision
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.evidence.FailureName
import com.eltavine.duckdetector.features.locationrisk.data.preferences.LocationCacheConsentStore
import com.eltavine.duckdetector.features.locationrisk.data.probes.*
import com.eltavine.duckdetector.features.locationrisk.domain.*
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class LocationRiskRepository(context: Context) : DetectorScanner<LocationRiskReport> {
    private val context = context.applicationContext
    override suspend fun scan(): LocationRiskReport = withContext(Dispatchers.IO) {
        try {
            LocationRiskReport(
                stage = LocationRiskStage.READY,
                contracts = LocationContractCollector().collect(),
                cache = CachedLocationCollector(context).collect(LocationCacheConsentStore(context).decision() == ConsentDecision.GRANTED),
                installedPackage = LocationPackageCollector(AndroidInstalledPackageInventoryReader(context)).collect(),
            )
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: Exception) {
            LocationRiskReport.failed(FailureName.describe(failure))
        }
    }
}
