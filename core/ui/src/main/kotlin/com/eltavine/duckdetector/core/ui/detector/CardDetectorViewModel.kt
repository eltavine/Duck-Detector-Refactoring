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

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import android.os.SystemClock
import com.eltavine.duckdetector.core.evidence.ScanEpoch
import com.eltavine.duckdetector.core.report.DetectorHeadline
import com.eltavine.duckdetector.core.scan.DetectorSummary
import com.eltavine.duckdetector.core.scan.ScanSessionRunner
import com.eltavine.duckdetector.core.scan.summarize
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext

/** The card a detector session shows, and whether its latest scan has finished. */
internal data class CardDetectorState<M : DetectorHeadline>(
    val ready: Boolean,
    val cardModel: M,
)

/**
 * Holds one detector's card across configuration changes and runs its scans.
 *
 * It starts scanning when created. While a scan runs it shows the card for the detector's loading
 * report, and [ScanSessionRunner] makes sure only the newest scan publishes its card.
 */
internal class CardDetectorViewModel<R : Any, M : DetectorHeadline>(
    private val detector: Detector<R, M>,
    private val scanner: DetectorScanner<R>,
    initialScan: ScanEpoch,
    private val clockNanos: () -> Long = SystemClock::elapsedRealtimeNanos,
) : ViewModel() {

    private var nextEpoch: ScanEpoch? = initialScan

    private val _state = MutableStateFlow(
        CardDetectorState(ready = false, cardModel = detector.describe(detector.loadingReport())),
    )
    val state: StateFlow<CardDetectorState<M>> = _state.asStateFlow()

    val summary: StateFlow<DetectorSummary> = state
        .map { it.summary() }
        .stateIn(viewModelScope, SharingStarted.Eagerly, state.value.summary())

    private val scans = ScanSessionRunner(viewModelScope)

    init {
        rescan()
    }

    fun rescan() {
        val epoch = nextEpoch ?: ScanEpoch.begin(clockNanos())
        nextEpoch = null
        scans.launch(
            begin = {
                val loading = detector.loadingReport()
                _state.update { it.copy(ready = false, cardModel = detector.describe(loading)) }
            },
            collect = { withContext(epoch) { scanner.scan() } },
            publish = { report ->
                _state.update { it.copy(ready = true, cardModel = detector.describe(report)) }
            },
        )
    }

    private fun CardDetectorState<M>.summary(): DetectorSummary = cardModel.summarize(detector.id, ready)

    companion object {
        fun <R : Any, M : DetectorHeadline> factory(
            detector: Detector<R, M>,
            initialScan: ScanEpoch,
            createScanner: () -> DetectorScanner<R>,
        ): ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T =
                CardDetectorViewModel(detector, createScanner(), initialScan) as T
        }
    }
}
