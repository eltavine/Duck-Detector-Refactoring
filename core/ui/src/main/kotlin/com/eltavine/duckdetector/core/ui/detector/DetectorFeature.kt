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
import androidx.compose.runtime.Stable
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.evidence.ScanEpoch
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.core.report.DeviceReport
import com.eltavine.duckdetector.core.scan.DetectorSummary
import kotlinx.coroutines.flow.StateFlow

/**
 * A detector as the application composes it.
 *
 * This is the whole integration surface of a detector: the application's generated card list
 * collects every feature, and everything central (coordination, dashboard, export, notifications,
 * the startup policy and settings) works on sessions and consent cards, so adding or changing a
 * detector touches only that detector and its catalog entry.
 */
public interface DetectorFeature {
    public val id: DetectorId

    /** How the application asks for each of the detector's consents; most detectors have none. */
    public val consentCards: List<ConsentCard> get() = emptyList()

    /** Binds the detector's state holder to the current composition's owner and returns its session. */
    @Composable
    public fun rememberSession(initialScan: ScanEpoch): DetectorSession
}

@Stable
public interface DetectorSession {
    public val id: DetectorId

    /** Published summary of the current scan, observed by the scan coordinator. */
    public val summary: StateFlow<DetectorSummary>

    /** Export projection of the current scan. */
    public fun report(): DetectorReport

    public fun rescan()

    /** The detector's own dashboard card, including any dialogs it owns. */
    @Composable
    public fun Card()
}

/** The device specification shown under the detector cards and appended to exports. */
public interface DeviceProfileFeature {
    @Composable
    public fun rememberSession(): DeviceProfileSession
}

@Stable
public interface DeviceProfileSession {
    public fun report(): DeviceReport

    @Composable
    public fun Card()
}
