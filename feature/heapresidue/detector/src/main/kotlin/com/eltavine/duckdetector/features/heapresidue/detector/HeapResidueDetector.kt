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

package com.eltavine.duckdetector.features.heapresidue.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.detector.DetectorSpecificApi
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.heapresidue.data.repository.HeapResidueRepository
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueReport
import com.eltavine.duckdetector.features.heapresidue.presentation.HeapResidueCardModelMapper
import com.eltavine.duckdetector.features.heapresidue.presentation.model.HeapResidueCardModel
import com.eltavine.duckdetector.features.heapresidue.presentation.toDetectorReport

/**
 * Zygote heap residue: observes exact startup argument strings in a fresh isolated ART heap snapshot as heuristic package traces.
 *
 * Collected by [HeapResidueRepository], judged by `HeapResidueReport.toDetectorStatus()` in the domain
 * layer, and described by [HeapResidueCardModelMapper].
 */
@DetectorSpecificApi
public object HeapResidueDetector : Detector<HeapResidueReport, HeapResidueCardModel> {
    override val id: DetectorId = DetectorId("heap_residue")

    override fun createScanner(context: Context): DetectorScanner<HeapResidueReport> = HeapResidueRepository(context)

    override fun loadingReport(): HeapResidueReport = HeapResidueReport.loading()

    override fun describe(report: HeapResidueReport): HeapResidueCardModel = HeapResidueCardModelMapper().map(report)

    override fun export(model: HeapResidueCardModel): DetectorReport = model.toDetectorReport()
}
