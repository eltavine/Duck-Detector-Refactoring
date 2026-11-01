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

package com.eltavine.duckdetector.features.zygisk.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskReport
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskStage
import com.eltavine.duckdetector.features.zygisk.domain.toDetectorStatus
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskImpactItemModel

internal fun buildImpactItems(
    report: ZygiskReport,
): List<ZygiskImpactItemModel> {
    return when (report.stage) {
        ZygiskStage.LOADING -> listOf(
            ZygiskImpactItemModel(
                text = "Collecting the cross-process FD trap result and the native runtime snapshot in parallel.",
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
        )

        ZygiskStage.FAILED -> listOf(
            ZygiskImpactItemModel(
                text = report.errorMessage ?: "Zygisk detection failed.",
                status = DetectorStatus.info(InfoKind.ERROR),
            ),
        )

        ZygiskStage.READY -> when (report.toDetectorStatus()) {
            DetectorStatus.danger() -> listOf(
                ZygiskImpactItemModel(
                    text = if (report.fdTrapDetected || report.nativeStrongHitCount > 0) {
                        "This process exposed direct runtime evidence or the cross-process specialization path behaved like a Zygisk-sanitized child process."
                    } else {
                        "Multiple heuristic families need review. Their convergence does not establish Zygisk injection."
                    },
                    status = DetectorStatus.danger(),
                ),
                ZygiskImpactItemModel(
                    text = "Read the individual findings together with Memory and Mount; runtime residue can also have legitimate causes.",
                    status = DetectorStatus.warning(),
                ),
            )

            DetectorStatus.warning() -> listOf(
                ZygiskImpactItemModel(
                    text = "Yellow means only weaker corroboration traces were found, not a single decisive runtime primitive on their own.",
                    status = DetectorStatus.warning(),
                ),
                ZygiskImpactItemModel(
                    text = "Read this together with Memory and Mount, which can still surface loader and mapping residue in parallel.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            DetectorStatus.allClear() -> listOf(
                ZygiskImpactItemModel(
                    text = "No direct runtime or converging heuristic signal surfaced in the current app process.",
                    status = DetectorStatus.allClear(),
                ),
                ZygiskImpactItemModel(
                    text = "A clean result reduces confidence in active Zygisk-style tampering for this process, but it does not prove the whole device is stock.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            else -> listOf(
                ZygiskImpactItemModel(
                    text = "The detector completed, but at least one major path was unavailable, so this result is support-only rather than clean.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                ZygiskImpactItemModel(
                    text = "Unavailable service binding, an unsupported heap helper, or a missing native snapshot can all reduce confidence without implying a positive detection.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )
        }
    }
}
