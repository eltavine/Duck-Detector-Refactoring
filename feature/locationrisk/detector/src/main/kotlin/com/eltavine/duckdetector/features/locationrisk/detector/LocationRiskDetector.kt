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

package com.eltavine.duckdetector.features.locationrisk.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorConsent
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.detector.DetectorSpecificApi
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.locationrisk.data.repository.LocationRiskRepository
import com.eltavine.duckdetector.features.locationrisk.domain.LocationRiskReport
import com.eltavine.duckdetector.features.locationrisk.presentation.LocationRiskCardModelMapper
import com.eltavine.duckdetector.features.locationrisk.presentation.model.LocationRiskCardModel
import com.eltavine.duckdetector.features.locationrisk.presentation.toDetectorReport

/**
 * Location Risk: Checks app-owned Location contracts, optional cached mock metadata and exact package context without retaining coordinates.
 *
 * Collected by [LocationRiskRepository], judged by `LocationRiskReport.toDetectorStatus()` in the domain
 * layer, and described by [LocationRiskCardModelMapper].
 */
@DetectorSpecificApi
public object LocationRiskDetector : Detector<LocationRiskReport, LocationRiskCardModel> {
    override val id: DetectorId = DetectorId("location_risk")

    override val consents: List<DetectorConsent> = listOf(LocationCacheConsent)

    override fun createScanner(context: Context): DetectorScanner<LocationRiskReport> = LocationRiskRepository(context)

    override fun loadingReport(): LocationRiskReport = LocationRiskReport.loading()

    override fun describe(report: LocationRiskReport): LocationRiskCardModel = LocationRiskCardModelMapper().map(report)

    override fun export(model: LocationRiskCardModel): DetectorReport = model.toDetectorReport()
}
