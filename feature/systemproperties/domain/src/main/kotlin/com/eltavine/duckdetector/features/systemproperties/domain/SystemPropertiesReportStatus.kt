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

package com.eltavine.duckdetector.features.systemproperties.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind

/**
 * Debug minus radio, in nanoseconds, when the system area is newer than debug and debug is newer
 * than radio. Any other order has no difference. A difference that overflows below zero is not shown.
 */
fun orderedPropertyAreaDelta(debugNanos: Long, systemNanos: Long, radioNanos: Long): Long? {
    if (systemNanos > debugNanos && debugNanos > radioNanos) {
        val delta = debugNanos - radioNanos
        if (delta >= 0L) {
            return delta
        }
    }
    return null
}

fun SystemPropertiesReport.toDetectorStatus(): DetectorStatus {
    return when (stage) {
        SystemPropertiesStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
        SystemPropertiesStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
        SystemPropertiesStage.READY -> when {
            hasDangerSignals -> DetectorStatus.danger()
            hasWarningSignals -> DetectorStatus.warning()
            hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
            else -> DetectorStatus.allClear()
        }
    }
}

fun SystemPropertiesReport.hasReducedCoverage(): Boolean {
    return !propAreaAvailable
}
