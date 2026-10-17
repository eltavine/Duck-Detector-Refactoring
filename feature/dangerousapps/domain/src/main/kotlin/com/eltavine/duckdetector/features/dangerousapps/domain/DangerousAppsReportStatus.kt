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

package com.eltavine.duckdetector.features.dangerousapps.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind

fun DangerousAppsReport.toDetectorStatus(): DetectorStatus {
    return when (stage) {
        DangerousAppsStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
        DangerousAppsStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
        DangerousAppsStage.READY -> when {
            hiddenCount > 0 -> DetectorStatus.danger()
            behaviorChecks.any { it.state == HmaCheckState.INCONSISTENT } -> DetectorStatus.warning()
            behaviorChecks.any { it.state == HmaCheckState.TIMING_ANOMALY } -> DetectorStatus.warning()
            detectedCount > 0 -> DetectorStatus.warning()
            suspiciousSharedStorageDenied -> DetectorStatus.warning()
            suspiciousLowPmInventory -> DetectorStatus.warning()
            packageVisibility == DangerousPackageVisibility.RESTRICTED -> DetectorStatus.info(
                InfoKind.ERROR
            )

            packageVisibility == DangerousPackageVisibility.UNKNOWN -> DetectorStatus.info(
                InfoKind.SUPPORT
            )

            behaviorChecks.any { it.state != HmaCheckState.CONSISTENT } -> DetectorStatus.info(InfoKind.SUPPORT)

            else -> DetectorStatus.allClear()
        }
    }
}
