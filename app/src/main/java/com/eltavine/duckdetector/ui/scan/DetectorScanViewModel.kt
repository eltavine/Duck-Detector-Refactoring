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

package com.eltavine.duckdetector.ui.scan

import android.os.SystemClock
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.core.scan.DetectorSummary
import com.eltavine.duckdetector.core.scan.ScanClock
import com.eltavine.duckdetector.core.scan.ScanCoordinator
import com.eltavine.duckdetector.features.dashboard.presentation.model.completedHistoricalVerdict
import com.eltavine.duckdetector.ui.scan.history.ScanHistoryJournal
import java.util.UUID
import kotlinx.coroutines.flow.StateFlow

/**
 * Hosts the scan coordinator for the lifetime of the activity's view models.
 *
 * Detector view models survive configuration changes, so the session they belong to must survive
 * them too; timing kept in composition restarted on every recreation and reported a near-zero
 * duration for a scan that had long finished.
 */
internal class DetectorScanViewModel(
    detectors: List<StateFlow<DetectorSummary>>,
    val history: ScanHistoryJournal,
) : ViewModel() {
    private val runId = UUID.randomUUID()
    val coordinator = ScanCoordinator(AndroidScanClock, viewModelScope, detectors) { state ->
        val verdict = state.completedHistoricalVerdict() ?: return@ScanCoordinator
        history.enqueue(runId, state.timeline.session, requireNotNull(state.timeline.completedAtEpochMillis), verdict)
    }

    companion object {
        fun factory(
            detectors: List<StateFlow<DetectorSummary>>,
            history: ScanHistoryJournal,
        ): ViewModelProvider.Factory {
            return object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return DetectorScanViewModel(detectors, history) as T
                }
            }
        }
    }
}

private object AndroidScanClock : ScanClock {
    override fun elapsedRealtimeMillis(): Long = SystemClock.elapsedRealtime()

    override fun currentTimeMillis(): Long = System.currentTimeMillis()
}
