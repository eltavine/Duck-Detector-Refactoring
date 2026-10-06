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

package com.eltavine.duckdetector.features.adbruntime.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.detector.DetectorSpecificApi
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.adbruntime.data.repository.AdbRuntimeRepository
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeReport
import com.eltavine.duckdetector.features.adbruntime.presentation.AdbRuntimeCardModelMapper
import com.eltavine.duckdetector.features.adbruntime.presentation.model.AdbRuntimeCardModel
import com.eltavine.duckdetector.features.adbruntime.presentation.toDetectorReport

/**
 * ADB Runtime: correlates Android debugging settings, USB and wireless ADB runtime signals, and init properties to detect contradictory ADB state.
 *
 * Collected by [AdbRuntimeRepository], judged by `AdbRuntimeReport.toDetectorStatus()` in the domain
 * layer, and described by [AdbRuntimeCardModelMapper].
 */
@DetectorSpecificApi
public object AdbRuntimeDetector : Detector<AdbRuntimeReport, AdbRuntimeCardModel> {
    override val id: DetectorId = DetectorId("adb_runtime")

    override fun createScanner(context: Context): DetectorScanner<AdbRuntimeReport> = AdbRuntimeRepository(context)

    override fun loadingReport(): AdbRuntimeReport = AdbRuntimeReport.loading()

    override fun describe(report: AdbRuntimeReport): AdbRuntimeCardModel = AdbRuntimeCardModelMapper().map(report)

    override fun export(model: AdbRuntimeCardModel): DetectorReport = model.toDetectorReport()
}
