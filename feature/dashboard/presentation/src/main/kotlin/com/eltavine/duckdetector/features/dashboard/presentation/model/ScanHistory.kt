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

package com.eltavine.duckdetector.features.dashboard.presentation.model

import com.eltavine.duckdetector.core.scan.ScanState

/** Persisted verdicts are observations of a completed scan, not device trust guarantees. */
public enum class HistoricalVerdict {
    DANGER,
    WARNING,
    CLEAR,
    INCONCLUSIVE,
}

public data class ScanHistoryCounts(
    val danger: Long = 0,
    val warning: Long = 0,
    val clear: Long = 0,
    val inconclusive: Long = 0,
) {
    public val coloredTotal: Long get() = danger + warning + clear

    public fun with(verdict: HistoricalVerdict): ScanHistoryCounts = when (verdict) {
        HistoricalVerdict.DANGER -> copy(danger = danger + 1)
        HistoricalVerdict.WARNING -> copy(warning = warning + 1)
        HistoricalVerdict.CLEAR -> copy(clear = clear + 1)
        HistoricalVerdict.INCONCLUSIVE -> copy(inconclusive = inconclusive + 1)
    }

    /** Display floor protects rare historical outcomes; persisted counts remain exact. */
    public fun segments(minFraction: Float = 0.08f): List<HistorySegment> {
        require(minFraction in 0f..(1f / 3f))
        val values = listOf(
            HistoricalVerdict.DANGER to danger,
            HistoricalVerdict.WARNING to warning,
            HistoricalVerdict.CLEAR to clear,
        ).filter { it.second > 0L }
        if (values.isEmpty()) return emptyList()
        val floor = minFraction.coerceAtMost(1f / values.size)
        val remainder = 1f - values.size * floor
        // Converting to Double first avoids overflowing Long when history grows.
        val total = values.sumOf { it.second.toDouble() }
        return values.map { (verdict, count) ->
            HistorySegment(verdict, floor + remainder * (count.toDouble() / total).toFloat())
        }
    }
}

public data class HistorySegment(
    val verdict: HistoricalVerdict,
    val fraction: Float,
)

/** Share exactly the dashboard's severity precedence, without treating unknown as clear. */
public fun ScanState.completedHistoricalVerdict(): HistoricalVerdict? {
    if (isLoading || detectors.isEmpty() || timeline.completedAtEpochMillis == null) return null
    return when (buildDashboardOverview(detectors).verdict) {
        OverviewVerdict.DANGER -> HistoricalVerdict.DANGER
        OverviewVerdict.WARNING -> HistoricalVerdict.WARNING
        OverviewVerdict.OK -> HistoricalVerdict.CLEAR
        OverviewVerdict.INFO -> HistoricalVerdict.INCONCLUSIVE
        OverviewVerdict.READY, OverviewVerdict.PENDING -> null
    }
}
