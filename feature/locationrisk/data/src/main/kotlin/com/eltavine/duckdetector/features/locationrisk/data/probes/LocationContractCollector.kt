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

import android.location.Location
import android.os.Build
import com.eltavine.duckdetector.features.locationrisk.domain.*
import kotlin.coroutines.cancellation.CancellationException

/** Only app-owned synthetic objects; no provider, service, real fix, hidden API or permission. */
internal class LocationContractCollector(private val createLocation: (String) -> Location = ::Location) {
    fun collect(): List<LocationContractCheck> = LocationContract.entries.map { contract ->
        if (contract == LocationContract.MOCK_FLAG && Build.VERSION.SDK_INT < 31) {
            LocationContractCheck(contract, LocationState.UNSUPPORTED)
        } else {
            val mismatches = linkedSetOf<LocationField>()
            val failure = try {
                repeat(2) { index ->
                    val location = createLocation("duckdetector_test_$index")
                    when (contract) {
                        LocationContract.VALUES -> checkValues(location, index, mismatches)
                        LocationContract.OPTIONAL_FIELDS -> checkFlags(location, mismatches)
                        LocationContract.RESET -> checkReset(location, mismatches)
                        LocationContract.MOCK_FLAG -> if (Build.VERSION.SDK_INT >= 31) checkMock(location, mismatches)
                    }
                }
                null
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (_: SecurityException) {
                LocationFailure.ACCESS_DENIED
            } catch (_: RuntimeException) {
                LocationFailure.PLATFORM_FAILURE
            }
            val state = when {
                mismatches.isNotEmpty() -> LocationState.OBSERVED
                failure == LocationFailure.ACCESS_DENIED -> LocationState.PERMISSION_LIMITED
                failure != null -> LocationState.UNAVAILABLE
                else -> LocationState.NOT_OBSERVED
            }
            LocationContractCheck(contract, state, mismatches, failure)
        }
    }

    private fun checkValues(location: Location, index: Int, mismatches: MutableSet<LocationField>) {
        val latitude = if (index == 0) 12.5 else -23.25
        val longitude = if (index == 0) -45.25 else 67.5
        val provider = "duckdetector_test_$index"
        location.latitude = latitude
        location.longitude = longitude
        location.provider = provider
        location.accuracy = 8f + index
        location.speed = 2f + index
        location.bearing = 90f + index
        location.altitude = 128.0 + index
        location.time = 123456789L + index
        location.elapsedRealtimeNanos = 987654321L + index
        with(mismatches) {
            if (location.latitude != latitude) add(LocationField.LATITUDE)
            if (location.longitude != longitude) add(LocationField.LONGITUDE)
            if (location.provider != provider) add(LocationField.PROVIDER)
            if (location.accuracy != 8f + index) add(LocationField.ACCURACY)
            if (location.speed != 2f + index) add(LocationField.SPEED)
            if (location.bearing != 90f + index) add(LocationField.BEARING)
            if (location.altitude != 128.0 + index) add(LocationField.ALTITUDE)
            if (location.time != 123456789L + index) add(LocationField.TIME)
            if (location.elapsedRealtimeNanos != 987654321L + index) add(LocationField.ELAPSED_TIME)
        }
    }

    private fun checkFlags(location: Location, mismatches: MutableSet<LocationField>) {
        if (location.hasAccuracy() || location.hasSpeed() || location.hasBearing() || location.hasAltitude()) {
            mismatches.add(LocationField.PRESENCE_FLAGS)
        }
        location.accuracy = 8f
        location.speed = 2f
        location.bearing = 90f
        location.altitude = 128.0
        if (!location.hasAccuracy() || !location.hasSpeed() || !location.hasBearing() || !location.hasAltitude()) {
            mismatches.add(LocationField.PRESENCE_FLAGS)
        }
    }

    private fun checkReset(location: Location, mismatches: MutableSet<LocationField>) {
        checkValues(location, 0, mismatches)
        location.reset()
        with(mismatches) {
            if (location.latitude != 0.0) add(LocationField.LATITUDE)
            if (location.longitude != 0.0) add(LocationField.LONGITUDE)
            if (location.provider != null) add(LocationField.PROVIDER)
            if (location.time != 0L) add(LocationField.TIME)
            if (location.elapsedRealtimeNanos != 0L) add(LocationField.ELAPSED_TIME)
            if (location.hasAccuracy() || location.hasSpeed() || location.hasBearing() || location.hasAltitude()) {
                add(LocationField.PRESENCE_FLAGS)
            }
        }
    }

    @androidx.annotation.RequiresApi(31)
    @Suppress("DEPRECATION")
    private fun checkMock(location: Location, mismatches: MutableSet<LocationField>) {
        location.isMock = true
        if (!location.isMock || !location.isFromMockProvider) mismatches.add(LocationField.MOCK_FLAG)
        location.isMock = false
        if (location.isMock || location.isFromMockProvider) mismatches.add(LocationField.MOCK_FLAG)
    }
}
