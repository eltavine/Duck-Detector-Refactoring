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
import android.os.SystemClock
import com.eltavine.duckdetector.features.locationrisk.domain.*
import kotlin.coroutines.cancellation.CancellationException

/** Each getter has its own failure boundary so freshness cannot erase an observed mock mark. */
@Suppress("DEPRECATION")
internal fun readCachedLocationMetadata(provider: CachedProvider, location: Location): CachedLocationCheck {
    // Do not read or retain coordinates, wall-clock fix times, extras or accuracy.
    val mock = readField { if (Build.VERSION.SDK_INT >= 31) location.isMock else location.isFromMockProvider }
    val age = readField { cacheAge(location.elapsedRealtimeNanos, SystemClock.elapsedRealtimeNanos()) }
    return CachedLocationCheck(
        provider = provider,
        state = when (mock.value) {
            true -> LocationState.OBSERVED
            false -> LocationState.NOT_OBSERVED
            null -> if (mock.failure == LocationFailure.ACCESS_DENIED) LocationState.PERMISSION_LIMITED else LocationState.UNAVAILABLE
        },
        mockMarked = mock.value,
        age = age.value ?: CacheAge.UNKNOWN,
        failure = mock.failure,
        ageFailure = age.failure,
    )
}

private data class FieldRead<T>(val value: T? = null, val failure: LocationFailure? = null)

private inline fun <T> readField(read: () -> T): FieldRead<T> = try {
    FieldRead(value = read())
} catch (cancellation: CancellationException) {
    throw cancellation
} catch (_: SecurityException) {
    FieldRead(failure = LocationFailure.ACCESS_DENIED)
} catch (_: RuntimeException) {
    FieldRead(failure = LocationFailure.PLATFORM_FAILURE)
}
