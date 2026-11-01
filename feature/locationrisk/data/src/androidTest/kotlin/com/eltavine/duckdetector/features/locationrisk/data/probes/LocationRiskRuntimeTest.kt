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
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.location.Location
import android.os.Build
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.eltavine.duckdetector.core.detector.ConsentDecision
import com.eltavine.duckdetector.features.locationrisk.data.preferences.LocationCacheConsentStore
import com.eltavine.duckdetector.features.locationrisk.data.repository.LocationRiskRepository
import com.eltavine.duckdetector.features.locationrisk.domain.*
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class LocationRiskRuntimeTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    @Test fun ordinaryUidAndUnmodifiedContracts() {
        assertTrue(Process.myUid() % 100000 >= 10000)
        val checks = LocationContractCollector().collect()
        assertEquals(4, checks.size)
        checks.forEach { check ->
            val expected = if (check.contract == LocationContract.MOCK_FLAG && Build.VERSION.SDK_INT < 31) LocationState.UNSUPPORTED else LocationState.NOT_OBSERVED
            assertEquals(check.toString(), expected, check.state)
        }
    }
    @Test fun broadGetterRewriteIsObservedWithoutRetainingValues() {
        val checks = LocationContractCollector { provider ->
            object : Location(provider) { override fun getLatitude() = 45.125 }
        }.collect()
        assertTrue(checks.first { it.contract == LocationContract.VALUES }.mismatches.contains(LocationField.LATITUDE))
        assertEquals(LocationState.OBSERVED, checks.first { it.contract == LocationContract.RESET }.state)
    }
    @Test fun hiddenMockGetterBreaksSyntheticRoundTrip() {
        if (Build.VERSION.SDK_INT < 31) return
        val checks = LocationContractCollector { provider ->
            object : Location(provider) { override fun isMock() = false }
        }.collect()
        assertEquals(LocationState.OBSERVED, checks.first { it.contract == LocationContract.MOCK_FLAG }.state)
    }
    @Test fun deniedProbeAndThrowingProbeAreDifferentFromNoMismatch() {
        val denied = LocationContractCollector { throw SecurityException("fixture") }.collect()
        assertTrue(denied.filter { it.state != LocationState.UNSUPPORTED }.all { it.state == LocationState.PERMISSION_LIMITED })
        val failed = LocationContractCollector { throw IllegalStateException("fixture") }.collect()
        assertTrue(failed.filter { it.state != LocationState.UNSUPPORTED }.all { it.state == LocationState.UNAVAILABLE })
    }
    @Test fun laterGetterFailurePreservesEarlierContractMismatch() {
        val checks = LocationContractCollector { provider ->
            object : Location(provider) {
                override fun getLatitude() = 45.125
                override fun getLongitude(): Double = throw IllegalStateException("fixture")
            }
        }.collect()
        val values = checks.first { it.contract == LocationContract.VALUES }
        assertEquals(LocationState.OBSERVED, values.state)
        assertEquals(setOf(LocationField.LATITUDE), values.mismatches)
        assertEquals(LocationFailure.PLATFORM_FAILURE, values.failure)
    }
    @Test fun disabledCacheNeverChecksPermissionOrQueriesService() {
        val inaccessible = object : ContextWrapper(context) {
            override fun checkSelfPermission(permission: String): Int = error("must not check")
            override fun getSystemService(name: String): Any = error("must not query")
        }
        assertEquals(LocationFailure.DISABLED_BY_USER, CachedLocationCollector(inaccessible).collect(false).failure)
    }
    @Test fun missingPermissionNeverQueriesService() {
        val denied = object : ContextWrapper(context) {
            override fun checkSelfPermission(permission: String) = PackageManager.PERMISSION_DENIED
            override fun getSystemService(name: String): Any = error("must not query")
        }
        assertEquals(LocationState.PERMISSION_LIMITED, CachedLocationCollector(denied).collect(true).state)
    }
    @Test fun optInQueriesOnlyCachedMetadataAndRevocationStopsIt() = runBlocking {
        val store = LocationCacheConsentStore(context)
        store.decide(false)
        assertEquals(ConsentDecision.DECLINED, store.decision())
        assertEquals(LocationFailure.DISABLED_BY_USER, LocationRiskRepository(context).scan().cache?.failure)
        try {
            store.decide(true)
            val report = LocationRiskRepository(context).scan()
            val granted = context.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED
            assertEquals(if (granted) LocationState.OBSERVED else LocationState.PERMISSION_LIMITED, report.cache?.state)
            assertTrue(report.cache!!.samples.size <= 3)
            if (granted) {
                assertEquals(3, report.cache!!.samples.size)
                if (Build.VERSION.SDK_INT == 29 && context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
                    assertEquals(LocationPermission.APPROXIMATE, report.cache!!.permission)
                    report.cache!!.samples.filter { it.provider != CachedProvider.NETWORK }.forEach {
                        assertEquals(it.toString(), LocationState.PERMISSION_LIMITED, it.state)
                    }
                }
            }
        } finally {
            store.decide(false)
        }
        assertEquals(LocationFailure.DISABLED_BY_USER, LocationRiskRepository(context).scan().cache?.failure)
    }
}
