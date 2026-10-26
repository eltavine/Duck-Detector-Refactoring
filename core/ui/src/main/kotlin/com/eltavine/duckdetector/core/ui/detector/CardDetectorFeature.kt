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

package com.eltavine.duckdetector.core.ui.detector

import androidx.compose.runtime.Composable
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.viewmodel.compose.viewModel
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.evidence.ScanEpoch
import com.eltavine.duckdetector.core.report.DetectorHeadline
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.core.scan.DetectorSummary
import kotlinx.coroutines.flow.StateFlow

/**
 * Shows [detector] on the dashboard as a card whose content is [card].
 *
 * This is the whole UI integration of a detector whose card only renders its model, which is
 * every detector except those whose card keeps state of its own. The session scans through the
 * detector's scanner, and it summarizes and exports from the card model that is currently shown.
 */
public class CardDetectorFeature<R : Any, M : DetectorHeadline>(
    private val detector: Detector<R, M>,
    override val consentCards: List<ConsentCard> = emptyList(),
    private val card: @Composable (M) -> Unit,
) : DetectorFeature {
    override val id: DetectorId = detector.id

    @Composable
    override fun rememberSession(initialScan: ScanEpoch): DetectorSession {
        val context = LocalContext.current
        // Every card session shares this view model class, so the detector id keeps them apart.
        val viewModel: CardDetectorViewModel<R, M> = viewModel(
            key = detector.id.value,
            factory = remember(context, initialScan) {
                CardDetectorViewModel.factory(detector, initialScan) {
                    detector.createScanner(context.applicationContext)
                }
            },
        )
        return remember(viewModel) { CardDetectorSession(detector, viewModel, card) }
    }
}

private class CardDetectorSession<R : Any, M : DetectorHeadline>(
    private val detector: Detector<R, M>,
    private val viewModel: CardDetectorViewModel<R, M>,
    private val card: @Composable (M) -> Unit,
) : DetectorSession {
    override val id: DetectorId = detector.id

    override val summary: StateFlow<DetectorSummary> = viewModel.summary

    override fun report(): DetectorReport = detector.export(viewModel.state.value.cardModel)

    override fun rescan() {
        viewModel.rescan()
    }

    @Composable
    override fun Card() {
        val state by viewModel.state.collectAsStateWithLifecycle()
        card(state.cardModel)
    }
}
