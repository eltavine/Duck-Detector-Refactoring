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

package com.eltavine.duckdetector.core.ui.model

data class DetectorStatus(
    val severity: DetectionSeverity,
    val infoKind: InfoKind? = null,
) {
    init {
        require(severity == DetectionSeverity.INFO || infoKind == null) {
            "Only INFO status can carry an InfoKind"
        }
    }

    companion object {
        fun info(kind: InfoKind) = DetectorStatus(DetectionSeverity.INFO, kind)
        fun allClear() = DetectorStatus(DetectionSeverity.ALL_CLEAR)
        fun warning() = DetectorStatus(DetectionSeverity.WARNING)
        fun danger() = DetectorStatus(DetectionSeverity.DANGER)
    }
}
