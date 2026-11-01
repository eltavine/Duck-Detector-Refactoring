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

package com.eltavine.duckdetector.core.scan

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch

/** Clock port so scan timing never reads platform clocks directly. */
public interface ScanClock {
    /** Monotonic milliseconds used for durations. */
    public fun elapsedRealtimeMillis(): Long

    /** Wall-clock milliseconds used for the reported completion time. */
    public fun currentTimeMillis(): Long
}

/**
 * Timing of one dashboard-wide scan session.
 *
 * A session starts when coordination starts or when any detector returns to loading after the
 * previous session finished, and finishes the first time every detector is ready.
 */
public data class ScanTimeline(
    val session: Int,
    val startedAtElapsedMillis: Long,
    val finishedAtElapsedMillis: Long? = null,
    val completedAtEpochMillis: Long? = null,
) {
    public val durationMillis: Long?
        get() = finishedAtElapsedMillis?.minus(startedAtElapsedMillis)?.coerceAtLeast(0L)

    /** Advances the session for the current loading state; returns this instance when nothing changes. */
    public fun advance(isLoading: Boolean, clock: ScanClock): ScanTimeline = when {
        isLoading && finishedAtElapsedMillis != null -> ScanTimeline(
            session = session + 1,
            startedAtElapsedMillis = clock.elapsedRealtimeMillis(),
        )

        !isLoading && finishedAtElapsedMillis == null -> copy(
            finishedAtElapsedMillis = clock.elapsedRealtimeMillis(),
            completedAtEpochMillis = clock.currentTimeMillis(),
        )

        else -> this
    }
}

public data class ScanState(
    val detectors: List<DetectorSummary>,
    val timeline: ScanTimeline,
) {
    public val isLoading: Boolean
        get() = detectors.any { !it.ready }

    public val readyCount: Int
        get() = detectors.count { it.ready }
}

/**
 * Owns scan progress, session identity and timing for a fixed set of detectors.
 *
 * Detectors keep running their own scans; the coordinator only observes what they publish, so
 * the UI renders [state] instead of reconstructing progress and timing from separate models.
 */
public class ScanCoordinator(
    private val clock: ScanClock,
    scope: CoroutineScope,
    detectors: List<StateFlow<DetectorSummary>>,
    private val onCompleted: (ScanState) -> Unit = {},
) {
    private val mutableState = MutableStateFlow(
        detectors.map { it.value }.let { initial ->
            ScanState(
                detectors = initial,
                timeline = ScanTimeline(session = 1, startedAtElapsedMillis = clock.elapsedRealtimeMillis())
                    .advance(isLoading = initial.any { !it.ready }, clock = clock),
            )
        },
    )

    public val state: StateFlow<ScanState> = mutableState.asStateFlow()

    init {
        publishCompletion(mutableState.value)
        if (detectors.isNotEmpty()) {
            scope.launch {
                combine(detectors) { it.toList() }.collect { summaries ->
                    val previous = mutableState.value
                    val next = ScanState(
                        detectors = summaries,
                        timeline = previous.timeline.advance(summaries.any { !it.ready }, clock),
                    )
                    mutableState.value = next
                    if (previous.timeline.completedAtEpochMillis == null) publishCompletion(next)
                }
            }
        }
    }

    private fun publishCompletion(state: ScanState) {
        if (state.detectors.isNotEmpty() && !state.isLoading &&
            state.timeline.completedAtEpochMillis != null
        ) {
            onCompleted(state)
        }
    }
}
