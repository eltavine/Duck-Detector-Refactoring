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

package com.eltavine.duckdetector.features.rootmanagers.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorConsent
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.detector.DetectorSpecificApi
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.rootmanagers.data.repository.RootManagersRepository
import com.eltavine.duckdetector.features.rootmanagers.domain.RootManagersReport
import com.eltavine.duckdetector.features.rootmanagers.presentation.RootManagersCardModelMapper
import com.eltavine.duckdetector.features.rootmanagers.presentation.model.RootManagersCardModel
import com.eltavine.duckdetector.features.rootmanagers.presentation.toDetectorReport

/**
 * Root Managers: finds root manager apps through launcher visibility, including renamed, re-signed,
 * or other-profile installs.
 *
 * Collected by [RootManagersRepository], judged by `RootManagersReport.toDetectorStatus()` in the
 * domain layer, and described by [RootManagersCardModelMapper].
 */
@DetectorSpecificApi
public object RootManagersDetector : Detector<RootManagersReport, RootManagersCardModel> {
    override val id: DetectorId = DetectorId("root_managers")

    override val consents: List<DetectorConsent> = listOf(RootManagersInstallerCanaryConsent)

    override fun createScanner(context: Context): DetectorScanner<RootManagersReport> = RootManagersRepository(context)

    override fun loadingReport(): RootManagersReport = RootManagersReport.loading()

    override fun describe(report: RootManagersReport): RootManagersCardModel = RootManagersCardModelMapper().map(report)

    override fun export(model: RootManagersCardModel): DetectorReport = model.toDetectorReport()
}
