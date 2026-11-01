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
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.eltavine.duckdetector.features.locationrisk.domain.*
import kotlin.coroutines.cancellation.CancellationException
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
@RunWith(AndroidJUnit4::class)
class CachedLocationMetadataTest {
    @Test fun mockMarkSurvivesTimestampFailure() {
        val location = object : Location("gps") {
            override fun isMock() = true
            override fun isFromMockProvider() = true
            override fun getElapsedRealtimeNanos(): Long = throw IllegalStateException("fixture")
        }
        val sample = readCachedLocationMetadata(CachedProvider.GPS, location)
        assertEquals(LocationState.OBSERVED, sample.state)
        assertEquals(true, sample.mockMarked)
        assertNull(sample.failure)
        assertEquals(CacheAge.UNKNOWN, sample.age)
        assertEquals(LocationFailure.PLATFORM_FAILURE, sample.ageFailure)
    }

    @Test fun timestampSurvivesMockGetterFailure() {
        val location = object : Location("gps") {
            override fun isMock(): Boolean = throw SecurityException("fixture")
            override fun isFromMockProvider(): Boolean = throw SecurityException("fixture")
            override fun getElapsedRealtimeNanos() = Long.MAX_VALUE
        }
        val sample = readCachedLocationMetadata(CachedProvider.GPS, location)
        assertEquals(LocationState.PERMISSION_LIMITED, sample.state)
        assertNull(sample.mockMarked)
        assertEquals(LocationFailure.ACCESS_DENIED, sample.failure)
        assertEquals(CacheAge.FUTURE, sample.age)
        assertNull(sample.ageFailure)
    }

    @Test fun getterArgumentFailureDoesNotMeanProviderAbsent() {
        val location = object : Location("gps") {
            override fun isMock(): Boolean = throw IllegalArgumentException("fixture")
            override fun isFromMockProvider(): Boolean = throw IllegalArgumentException("fixture")
        }
        val sample = readCachedLocationMetadata(CachedProvider.GPS, location)
        assertEquals(LocationState.UNAVAILABLE, sample.state)
        assertEquals(LocationFailure.PLATFORM_FAILURE, sample.failure)
    }

    @Test fun realCoordinatesAndOtherMetadataAreNeverRead() {
        val location = object : Location("gps") {
            override fun getLatitude(): Double = error("coordinate access")
            override fun getLongitude(): Double = error("coordinate access")
            override fun getTime(): Long = error("wall time access")
            override fun getAccuracy(): Float = error("accuracy access")
            override fun getExtras(): android.os.Bundle = error("extras access")
        }
        assertEquals(LocationState.NOT_OBSERVED, readCachedLocationMetadata(CachedProvider.GPS, location).state)
    }

    @Test fun cancellationIsNotConvertedToUnavailableEvidence() {
        val location = object : Location("gps") {
            override fun isMock(): Boolean = throw CancellationException("fixture")
            override fun isFromMockProvider(): Boolean = throw CancellationException("fixture")
        }
        try {
            readCachedLocationMetadata(CachedProvider.GPS, location)
            fail("Cancellation must propagate")
        } catch (_: CancellationException) {
            // The caller owns cancellation, rather than a metadata result.
        }
    }
}
