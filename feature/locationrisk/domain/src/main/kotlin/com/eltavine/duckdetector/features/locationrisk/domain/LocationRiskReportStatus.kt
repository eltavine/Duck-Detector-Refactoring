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

package com.eltavine.duckdetector.features.locationrisk.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind

fun LocationRiskReport.toDetectorStatus(): DetectorStatus = when {
    stage == LocationRiskStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
    stage == LocationRiskStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
    contracts.any { it.state == LocationState.OBSERVED } ||
        cache?.samples.orEmpty().any { it.hasMockEvidence() } ||
        installedPackage?.state == LocationState.OBSERVED -> DetectorStatus.warning()
    contracts.any { it.failure == LocationFailure.PLATFORM_FAILURE } ||
        cache?.failure == LocationFailure.PLATFORM_FAILURE || cache?.samples.orEmpty().any {
            it.failure == LocationFailure.PLATFORM_FAILURE || it.ageFailure == LocationFailure.PLATFORM_FAILURE
        } ||
        installedPackage?.failure == LocationFailure.PLATFORM_FAILURE -> DetectorStatus.info(InfoKind.ERROR)
    contracts.isEmpty() || contracts.any { it.state == LocationState.UNAVAILABLE || it.state == LocationState.PERMISSION_LIMITED } ->
        DetectorStatus.info(InfoKind.SUPPORT)
    else -> DetectorStatus.info(InfoKind.SUPPORT)
}

/** A cached mark warrants review even when its age is unknown; it does not establish current spoofing. */
fun CachedLocationCheck.hasMockEvidence(): Boolean = state == LocationState.OBSERVED && mockMarked == true
