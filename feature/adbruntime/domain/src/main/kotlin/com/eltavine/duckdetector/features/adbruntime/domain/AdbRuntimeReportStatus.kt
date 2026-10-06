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

package com.eltavine.duckdetector.features.adbruntime.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind

fun AdbRuntimeReport.toDetectorStatus(): DetectorStatus = when (stage) {
    AdbRuntimeStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
    AdbRuntimeStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
    AdbRuntimeStage.READY -> {
        val findings = findings()
        when {
            findings.isNotEmpty() -> DetectorStatus.danger()
            isAdbActive() -> DetectorStatus.warning()
            !probed -> DetectorStatus.info(InfoKind.SUPPORT)
            else -> DetectorStatus.allClear()
        }
    }
}
