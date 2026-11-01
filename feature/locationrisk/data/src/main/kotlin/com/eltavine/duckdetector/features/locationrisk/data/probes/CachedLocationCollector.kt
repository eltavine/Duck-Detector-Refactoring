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

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.os.SystemClock
import com.eltavine.duckdetector.features.locationrisk.domain.*
import kotlin.coroutines.cancellation.CancellationException

internal class CachedLocationCollector(private val context: Context) {
    fun collect(enabled: Boolean): CachedLocationContext {
        if (!enabled) return CachedLocationContext(LocationState.UNAVAILABLE, failure = LocationFailure.DISABLED_BY_USER)
        return try {
            val permission = when {
                context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED -> LocationPermission.PRECISE
                context.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED -> LocationPermission.APPROXIMATE
                else -> LocationPermission.NONE
            }
            if (permission == LocationPermission.NONE) {
                return CachedLocationContext(LocationState.PERMISSION_LIMITED, failure = LocationFailure.ACCESS_DENIED)
            }
            val manager = context.getSystemService(LocationManager::class.java)
                ?: return CachedLocationContext(LocationState.UNAVAILABLE, permission, failure = LocationFailure.PLATFORM_FAILURE)
            val sampledAt = SystemClock.elapsedRealtime()
            val locationEnabled = manager.isLocationEnabled
            val samples = CachedProvider.entries.map { read(manager, it) }
            CachedLocationContext(LocationState.OBSERVED, permission, locationEnabled, samples, sampledAt)
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (_: SecurityException) {
            CachedLocationContext(LocationState.PERMISSION_LIMITED, failure = LocationFailure.ACCESS_DENIED)
        } catch (_: RuntimeException) {
            CachedLocationContext(LocationState.UNAVAILABLE, failure = LocationFailure.PLATFORM_FAILURE)
        }
    }

    @Suppress("MissingPermission")
    private fun read(manager: LocationManager, provider: CachedProvider): CachedLocationCheck = try {
        val name = when (provider) {
            CachedProvider.GPS -> LocationManager.GPS_PROVIDER
            CachedProvider.NETWORK -> LocationManager.NETWORK_PROVIDER
            CachedProvider.PASSIVE -> LocationManager.PASSIVE_PROVIDER
        }
        val location = manager.getLastKnownLocation(name)
        if (location == null) {
            CachedLocationCheck(provider, LocationState.UNAVAILABLE, failure = LocationFailure.NO_CACHE)
        } else {
            readCachedLocationMetadata(provider, location)
        }
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (_: IllegalArgumentException) {
        CachedLocationCheck(provider, LocationState.UNSUPPORTED, failure = LocationFailure.PROVIDER_ABSENT)
    } catch (_: SecurityException) {
        CachedLocationCheck(provider, LocationState.PERMISSION_LIMITED, failure = LocationFailure.ACCESS_DENIED)
    } catch (_: RuntimeException) {
        CachedLocationCheck(provider, LocationState.UNAVAILABLE, failure = LocationFailure.PLATFORM_FAILURE)
    }
}

internal fun cacheAge(fixNanos: Long, nowNanos: Long): CacheAge = when {
    fixNanos <= 0 || nowNanos < 0 -> CacheAge.UNKNOWN
    fixNanos > nowNanos -> CacheAge.FUTURE
    nowNanos - fixNanos > 300_000_000_000L -> CacheAge.STALE
    else -> CacheAge.RECENT
}
