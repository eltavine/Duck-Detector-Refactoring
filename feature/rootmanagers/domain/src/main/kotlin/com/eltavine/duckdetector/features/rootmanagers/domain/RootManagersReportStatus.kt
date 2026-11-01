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

package com.eltavine.duckdetector.features.rootmanagers.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind

/** The single reading of a report; status and wording both derive from it, so they cannot disagree. */
enum class RootManagersOutcome {
    SCANNING,
    FAILED,

    /** An identified manager disabled its launcher icon: presence plus concealment. */
    CONCEALED_MANAGER,
    MANAGER_FOUND,
    WEAK_MATCH,
    PERMISSION_ANCHOR,
    ENUMERATION_UNAVAILABLE,
    PROFILES_NOT_ENUMERATED,

    /** Nothing matched, but a probe could not read part of the evidence, so absence is not shown. */
    PARTIAL,
    CLEAN,
}

fun RootManagersReport.outcome(): RootManagersOutcome = when (stage) {
    RootManagersStage.LOADING -> RootManagersOutcome.SCANNING
    RootManagersStage.FAILED -> RootManagersOutcome.FAILED
    RootManagersStage.READY -> when {
        entries.any { it.concealed } -> RootManagersOutcome.CONCEALED_MANAGER
        entries.any { it.confidence != RootManagerConfidence.LOW } -> RootManagersOutcome.MANAGER_FOUND
        installerCanary.state == InstallerCanaryState.PERMISSION_OWNER_OBSERVED -> RootManagersOutcome.PERMISSION_ANCHOR
        entries.isNotEmpty() -> RootManagersOutcome.WEAK_MATCH
        enumerationState == RootManagersEnumerationState.UNAVAILABLE -> RootManagersOutcome.ENUMERATION_UNAVAILABLE
        enumerationState == RootManagersEnumerationState.UNDECIDABLE -> RootManagersOutcome.PROFILES_NOT_ENUMERATED
        !complete -> RootManagersOutcome.PARTIAL
        else -> RootManagersOutcome.CLEAN
    }
}

/**
 * An identified manager that also hid its launcher icon is danger, as Dangerous Apps rates an app
 * hidden from PackageManager: presence plus concealment. Any other identified manager is a warning;
 * a weak-only hit, a scan that never enumerated the profiles and a partial evaluation are all
 * informational, because none of them is evidence of absence.
 */
fun RootManagersReport.toDetectorStatus(): DetectorStatus = when (outcome()) {
    RootManagersOutcome.SCANNING -> DetectorStatus.info(InfoKind.SUPPORT)
    RootManagersOutcome.FAILED -> DetectorStatus.info(InfoKind.ERROR)
    RootManagersOutcome.CONCEALED_MANAGER -> DetectorStatus.danger()
    RootManagersOutcome.MANAGER_FOUND -> DetectorStatus.warning()
    RootManagersOutcome.WEAK_MATCH, RootManagersOutcome.PERMISSION_ANCHOR -> DetectorStatus.info(InfoKind.SUPPORT)
    RootManagersOutcome.ENUMERATION_UNAVAILABLE -> DetectorStatus.info(InfoKind.ERROR)
    RootManagersOutcome.PROFILES_NOT_ENUMERATED -> DetectorStatus.info(InfoKind.SUPPORT)
    RootManagersOutcome.PARTIAL -> DetectorStatus.info(InfoKind.SUPPORT)
    RootManagersOutcome.CLEAN -> DetectorStatus.allClear()
}
