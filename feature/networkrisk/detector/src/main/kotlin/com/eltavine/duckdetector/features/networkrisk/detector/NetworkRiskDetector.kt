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

package com.eltavine.duckdetector.features.networkrisk.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.detector.DetectorSpecificApi
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.networkrisk.data.repository.NetworkRiskRepository
import com.eltavine.duckdetector.features.networkrisk.domain.NetworkRiskReport
import com.eltavine.duckdetector.features.networkrisk.presentation.NetworkRiskCardModelMapper
import com.eltavine.duckdetector.features.networkrisk.presentation.model.NetworkRiskCardModel
import com.eltavine.duckdetector.features.networkrisk.presentation.toDetectorReport

/**
 * Network Risk: reports caller-visible network, proxy configuration and exact client package evidence with explicit coverage limits.
 *
 * Collected by [NetworkRiskRepository], judged by `NetworkRiskReport.toDetectorStatus()` in the domain
 * layer, and described by [NetworkRiskCardModelMapper].
 */
@DetectorSpecificApi
public object NetworkRiskDetector : Detector<NetworkRiskReport, NetworkRiskCardModel> {
    override val id: DetectorId = DetectorId("network_risk")

    override fun createScanner(context: Context): DetectorScanner<NetworkRiskReport> = NetworkRiskRepository(context)

    override fun loadingReport(): NetworkRiskReport = NetworkRiskReport.loading()

    override fun describe(report: NetworkRiskReport): NetworkRiskCardModel = NetworkRiskCardModelMapper().map(report)

    override fun export(model: NetworkRiskCardModel): DetectorReport = model.toDetectorReport()
}
