/*
 * Copyright 2026 Duck Apps Contributor
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

package com.eltavine.duckdetector.core.ui.components

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind

/** The tag a folded evidence section shows on its header. */
public enum class SectionSeverity {
    HIGH,
    MEDIUM,

    /** A probe in the section failed, so its rows were not evaluated rather than found clean. */
    PROBE_ERROR,
}

/**
 * Danger takes precedence over Warning, and actionable evidence over a failed probe. A failed
 * probe still gets a tag: sections start folded, and an untagged header reads as clean.
 */
public fun highestSectionSeverity(statuses: Iterable<DetectorStatus>): SectionSeverity? {
    var warning = false
    var probeError = false
    for (status in statuses) {
        when (status.severity) {
            DetectionSeverity.DANGER -> return SectionSeverity.HIGH
            DetectionSeverity.WARNING -> warning = true
            DetectionSeverity.INFO -> if (status.infoKind == InfoKind.ERROR) probeError = true
            DetectionSeverity.ALL_CLEAR -> Unit
        }
    }
    return when {
        warning -> SectionSeverity.MEDIUM
        probeError -> SectionSeverity.PROBE_ERROR
        else -> null
    }
}

/** For sections whose tag is derived from the detector's own header facts, not from rows. */
public fun DetectionSeverity.toSectionSeverity(): SectionSeverity? = when (this) {
    DetectionSeverity.DANGER -> SectionSeverity.HIGH
    DetectionSeverity.WARNING -> SectionSeverity.MEDIUM
    DetectionSeverity.INFO, DetectionSeverity.ALL_CLEAR -> null
}

internal fun SectionSeverity.representativeStatus(): DetectorStatus = when (this) {
    SectionSeverity.HIGH -> DetectorStatus.danger()
    SectionSeverity.MEDIUM -> DetectorStatus.warning()
    SectionSeverity.PROBE_ERROR -> DetectorStatus.info(InfoKind.ERROR)
}
