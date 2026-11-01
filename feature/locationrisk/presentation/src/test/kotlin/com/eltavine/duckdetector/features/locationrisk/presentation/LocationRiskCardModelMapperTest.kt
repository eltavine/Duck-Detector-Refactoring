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

package com.eltavine.duckdetector.features.locationrisk.presentation

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.report.ReportBlock
import com.eltavine.duckdetector.features.locationrisk.domain.*
import org.junit.Assert.*
import org.junit.Test

class LocationRiskCardModelMapperTest {
    private val mapper = LocationRiskCardModelMapper()
    @Test fun `empty checks say not evaluated`() {
        assertEquals("Local contracts not evaluated", mapper.map(ready()).verdict)
    }
    @Test fun `missing package context never claims visibility was observed`() {
        val rows = mapper.map(ready()).sections.single { it.key == "package" }.rows
        assertTrue(rows.all { it.value == "Unavailable" })
    }
    @Test fun `App and SDK export share verdict and severity`() {
        val report = ready().copy(contracts = listOf(LocationContractCheck(
            LocationContract.VALUES, LocationState.OBSERVED, setOf(LocationField.LATITUDE),
        )))
        val model = mapper.map(report)
        val export = model.toDetectorReport()
        assertEquals(model.verdict, export.verdict)
        assertEquals(DetectionSeverity.WARNING, export.severity)
        assertTrue(export.blocks.filterIsInstance<ReportBlock.Rows>().flatMap { it.rows }.any { it.detail?.contains("LATITUDE") == true })
    }
    @Test fun `synthetic mock mismatch is separate from real cached mock context`() {
        val model = mapper.map(ready().copy(contracts = listOf(LocationContractCheck(LocationContract.MOCK_FLAG, LocationState.OBSERVED))))
        assertEquals("Unavailable", model.headerFacts[1].value)
        assertEquals(DetectionSeverity.WARNING, model.headerFacts[0].status.severity)
    }
    @Test fun `cached mock warns in header detail and export while stale freshness stays inconclusive`() {
        val model = mapper.map(ready().copy(cache = CachedLocationContext(LocationState.OBSERVED,
            samples = listOf(CachedLocationCheck(CachedProvider.GPS, LocationState.OBSERVED, true, CacheAge.STALE)),
        )))
        val rows = model.sections.single { it.key == "cache" }.rows
        assertEquals(DetectionSeverity.WARNING, model.status.severity)
        assertEquals("Cached mock location observed", model.verdict)
        assertEquals(DetectionSeverity.WARNING, model.headerFacts[1].status.severity)
        assertEquals(DetectionSeverity.WARNING, rows.single { it.label == "GPS mock marker" }.status.severity)
        assertEquals(DetectionSeverity.INFO, rows.single { it.label == "GPS freshness" }.status.severity)
        assertEquals(DetectionSeverity.WARNING, model.toDetectorReport().severity)
        assertTrue(rows.any { it.value == "Inconclusive" })
        assertEquals("Observed", model.headerFacts[1].value)
    }
    @Test fun `denied and disabled access remain distinct`() {
        val denied = mapper.map(ready().copy(cache = CachedLocationContext(LocationState.PERMISSION_LIMITED, failure = LocationFailure.ACCESS_DENIED)))
        val disabled = mapper.map(ready().copy(cache = CachedLocationContext(LocationState.UNAVAILABLE, failure = LocationFailure.DISABLED_BY_USER)))
        assertEquals("Permission limited", denied.headerFacts[3].value)
        assertEquals("Unavailable", disabled.headerFacts[3].value)
        assertTrue(disabled.sections.single { it.key == "cache" }.rows.first().detail!!.contains("Disabled by default"))
    }
    @Test fun `package is unverified scoped context and not activity`() {
        val model = mapper.map(ready().copy(installedPackage = LocationPackageContext(LocationState.OBSERVED, "RESTRICTED")))
        val details = model.sections.single { it.key == "package" }.rows.mapNotNull { it.detail }.joinToString()
        assertTrue(details.contains("identity unverified"))
        assertTrue(details.contains("caller user/profile"))
        assertEquals(DetectionSeverity.WARNING, model.headerFacts[2].status.severity)
        assertEquals(DetectionSeverity.WARNING, model.status.severity)
        assertEquals("Location reference package observed", model.verdict)
        assertEquals(DetectionSeverity.WARNING, model.sections.single { it.key == "package" }.rows.first().status.severity)
        assertEquals(DetectionSeverity.INFO, model.sections.single { it.key == "package" }.rows.last().status.severity)
        assertEquals(model.verdict, model.toDetectorReport().verdict)
        assertEquals(DetectionSeverity.WARNING, model.toDetectorReport().severity)
    }
    @Test fun `one unmarked cache cannot hide denied providers`() {
        val model = mapper.map(ready().copy(cache = CachedLocationContext(LocationState.OBSERVED,
            samples = listOf(
                CachedLocationCheck(CachedProvider.GPS, LocationState.PERMISSION_LIMITED, failure = LocationFailure.ACCESS_DENIED),
                CachedLocationCheck(CachedProvider.NETWORK, LocationState.NOT_OBSERVED, false, CacheAge.RECENT),
                CachedLocationCheck(CachedProvider.PASSIVE, LocationState.PERMISSION_LIMITED, failure = LocationFailure.ACCESS_DENIED),
            ),
        )))
        assertEquals("Inconclusive", model.headerFacts[1].value)
        assertTrue(model.sections.single { it.key == "cache" }.rows.any { it.value == "Permission limited" })
    }
    @Test fun `partial local failures remain visible in verdict and export`() {
        val checks = LocationContract.entries.map { contract ->
            if (contract == LocationContract.RESET) LocationContractCheck(contract, LocationState.UNAVAILABLE, failure = LocationFailure.PLATFORM_FAILURE)
            else LocationContractCheck(contract, LocationState.NOT_OBSERVED)
        }
        val model = mapper.map(ready().copy(contracts = checks))
        assertEquals("Local contracts partially evaluated", model.verdict)
        assertEquals(model.verdict, model.toDetectorReport().verdict)
        assertEquals("Inconclusive", model.headerFacts[0].value)
    }
    @Test fun `pre31 unsupported mock round trip does not hide completed local checks`() {
        val checks = LocationContract.entries.map { contract -> LocationContractCheck(contract,
            if (contract == LocationContract.MOCK_FLAG) LocationState.UNSUPPORTED else LocationState.NOT_OBSERVED,
        ) }
        assertEquals("No local contract mismatch observed", mapper.map(ready().copy(contracts = checks)).verdict)
    }
    @Test fun `mock evidence and freshness failures both survive export`() {
        val model = mapper.map(ready().copy(cache = CachedLocationContext(LocationState.OBSERVED, samples = listOf(
            CachedLocationCheck(CachedProvider.GPS, LocationState.OBSERVED, true, ageFailure = LocationFailure.PLATFORM_FAILURE),
        ))))
        assertEquals("Observed", model.headerFacts[1].value)
        assertEquals(DetectionSeverity.WARNING, model.status.severity)
        val cacheRows = model.sections.single { it.key == "cache" }.rows
        assertEquals(com.eltavine.duckdetector.core.evidence.InfoKind.ERROR, cacheRows.single { it.label == "GPS freshness" }.status.infoKind)
        val rows = model.toDetectorReport().blocks.filterIsInstance<ReportBlock.Rows>().flatMap { it.rows }
        assertTrue(rows.any { it.label == "GPS mock marker" && it.value == "Observed" })
        assertTrue(rows.any { it.label == "GPS freshness" && it.detail?.contains("Platform query failed") == true })
    }
    private fun ready() = LocationRiskReport(LocationRiskStage.READY)
}
