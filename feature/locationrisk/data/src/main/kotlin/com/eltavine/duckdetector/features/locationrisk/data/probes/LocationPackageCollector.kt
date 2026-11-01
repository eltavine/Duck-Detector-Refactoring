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

package com.eltavine.duckdetector.features.locationrisk.data.probes

import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageInventoryReader
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageInventoryResult
import com.eltavine.duckdetector.features.locationrisk.domain.*
import kotlin.coroutines.cancellation.CancellationException

internal class LocationPackageCollector(private val reader: InstalledPackageInventoryReader) {
    fun collect(): LocationPackageContext = try {
        when (val result = reader.read()) {
            is InstalledPackageInventoryResult.Available -> LocationPackageContext(
                if (PACKAGE_NAME in result.inventory.packageNames) LocationState.OBSERVED else LocationState.NOT_OBSERVED,
                result.inventory.visibility.name,
            )
            is InstalledPackageInventoryResult.Unavailable -> LocationPackageContext(
                LocationState.UNAVAILABLE, "UNKNOWN", LocationFailure.PLATFORM_FAILURE,
            )
        }
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (_: SecurityException) {
        LocationPackageContext(LocationState.PERMISSION_LIMITED, "UNKNOWN", LocationFailure.ACCESS_DENIED)
    } catch (_: RuntimeException) {
        LocationPackageContext(LocationState.UNAVAILABLE, "UNKNOWN", LocationFailure.PLATFORM_FAILURE)
    }
    companion object { const val PACKAGE_NAME = "com.vincenthzr.locationspoofer" }
}
