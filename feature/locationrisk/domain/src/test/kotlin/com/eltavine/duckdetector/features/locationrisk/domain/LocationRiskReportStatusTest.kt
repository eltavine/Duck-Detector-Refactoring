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

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.evidence.InfoKind
import org.junit.Assert.assertEquals
import org.junit.Test

class LocationRiskReportStatusTest {
    @Test fun `failures and unevaluated reports are not clean`() {
        assertEquals(InfoKind.ERROR, LocationRiskReport.failed("failure").toDetectorStatus().infoKind)
        assertEquals(InfoKind.SUPPORT, LocationRiskReport.loading().toDetectorStatus().infoKind)
        assertEquals(DetectionSeverity.INFO, ready().toDetectorStatus().severity)
    }
    @Test fun `contract mismatch alone raises warning`() {
        LocationContract.entries.forEach { contract ->
            val check = LocationContractCheck(contract, LocationState.OBSERVED, setOf(LocationField.MOCK_FLAG))
            assertEquals(DetectionSeverity.WARNING, ready(listOf(check)).toDetectorStatus().severity)
        }
    }
    @Test fun `cached mock marks warn for every age without establishing current activity`() {
        CacheAge.entries.forEach { age ->
            val report = ready(clean()).copy(cache = CachedLocationContext(LocationState.OBSERVED, samples = listOf(
                CachedLocationCheck(CachedProvider.GPS, LocationState.OBSERVED, mockMarked = true, age = age),
            )))
            assertEquals(DetectionSeverity.WARNING, report.toDetectorStatus().severity)
        }
    }
    @Test fun `every coverage limitation remains informational`() {
        LocationState.entries.filter { it != LocationState.OBSERVED }.forEach { state ->
            assertEquals(DetectionSeverity.INFO, ready(listOf(LocationContractCheck(LocationContract.VALUES, state))).toDetectorStatus().severity)
        }
    }
    @Test fun `clean local contracts never authenticate a location`() {
        assertEquals(DetectionSeverity.INFO, ready(clean()).toDetectorStatus().severity)
    }
    @Test fun `freshness failure cannot erase an observed mock warning`() {
        val report = ready(clean()).copy(cache = CachedLocationContext(LocationState.OBSERVED, samples = listOf(
            CachedLocationCheck(CachedProvider.GPS, LocationState.OBSERVED, true, ageFailure = LocationFailure.PLATFORM_FAILURE),
        )))
        assertEquals(DetectionSeverity.WARNING, report.toDetectorStatus().severity)
    }
    @Test fun `reference package presence warns without requiring cache or contract evidence`() {
        val report = ready(clean()).copy(installedPackage = LocationPackageContext(LocationState.OBSERVED, "RESTRICTED"))
        assertEquals(DetectionSeverity.WARNING, report.toDetectorStatus().severity)
    }
    @Test fun `unmarked caches and limited package or mock states remain informational`() {
        LocationState.entries.filter { it != LocationState.OBSERVED }.forEach { state ->
            val report = ready(clean()).copy(
                installedPackage = LocationPackageContext(state, "UNKNOWN"),
                cache = CachedLocationContext(LocationState.OBSERVED, samples = listOf(
                    CachedLocationCheck(CachedProvider.GPS, state, mockMarked = true),
                    CachedLocationCheck(CachedProvider.NETWORK, LocationState.NOT_OBSERVED, false, CacheAge.STALE),
                )),
            )
            assertEquals(DetectionSeverity.INFO, report.toDetectorStatus().severity)
        }
    }
    @Test fun `age failure without a mock mark remains an informational error`() {
        val report = ready(clean()).copy(cache = CachedLocationContext(LocationState.OBSERVED, samples = listOf(
            CachedLocationCheck(CachedProvider.GPS, LocationState.NOT_OBSERVED, false, ageFailure = LocationFailure.PLATFORM_FAILURE),
        )))
        assertEquals(DetectionSeverity.INFO, report.toDetectorStatus().severity)
        assertEquals(InfoKind.ERROR, report.toDetectorStatus().infoKind)
    }
    private fun clean() = LocationContract.entries.map { LocationContractCheck(it, LocationState.NOT_OBSERVED) }
    private fun ready(checks: List<LocationContractCheck> = emptyList()) = LocationRiskReport(LocationRiskStage.READY, checks)
}
