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

package com.eltavine.duckdetector.features.locationrisk.domain

enum class LocationRiskStage { LOADING, READY, FAILED }
enum class LocationState { OBSERVED, NOT_OBSERVED, UNAVAILABLE, PERMISSION_LIMITED, UNSUPPORTED, INCONCLUSIVE }
enum class LocationFailure { ACCESS_DENIED, PLATFORM_FAILURE, PROVIDER_ABSENT, NO_CACHE, DISABLED_BY_USER }
enum class LocationContract { VALUES, OPTIONAL_FIELDS, RESET, MOCK_FLAG }
enum class LocationField { LATITUDE, LONGITUDE, PROVIDER, ACCURACY, SPEED, BEARING, ALTITUDE, TIME, ELAPSED_TIME, PRESENCE_FLAGS, MOCK_FLAG }

/** OBSERVED means a contract violation, not a real mock fix or attribution to a particular module. */
data class LocationContractCheck(
    val contract: LocationContract,
    val state: LocationState,
    val mismatches: Set<LocationField> = emptySet(),
    val failure: LocationFailure? = null,
)
enum class CachedProvider { GPS, NETWORK, PASSIVE }
enum class CacheAge { RECENT, STALE, FUTURE, UNKNOWN }
enum class LocationPermission { NONE, APPROXIMATE, PRECISE }
data class CachedLocationCheck(
    val provider: CachedProvider,
    val state: LocationState,
    val mockMarked: Boolean? = null,
    val age: CacheAge = CacheAge.UNKNOWN,
    val failure: LocationFailure? = null,
    val ageFailure: LocationFailure? = null,
)
data class CachedLocationContext(
    val state: LocationState,
    val permission: LocationPermission = LocationPermission.NONE,
    val locationEnabled: Boolean? = null,
    val samples: List<CachedLocationCheck> = emptyList(),
    val sampledAtElapsedMs: Long? = null,
    val failure: LocationFailure? = null,
)
data class LocationPackageContext(
    val state: LocationState,
    val visibility: String,
    val failure: LocationFailure? = null,
)
data class LocationRiskReport(
    val stage: LocationRiskStage,
    val contracts: List<LocationContractCheck> = emptyList(),
    val cache: CachedLocationContext? = null,
    val installedPackage: LocationPackageContext? = null,
    val errorMessage: String? = null,
) {
    companion object {
        fun loading(): LocationRiskReport = LocationRiskReport(LocationRiskStage.LOADING)
        fun failed(message: String): LocationRiskReport = LocationRiskReport(LocationRiskStage.FAILED, errorMessage = message)
    }
}
