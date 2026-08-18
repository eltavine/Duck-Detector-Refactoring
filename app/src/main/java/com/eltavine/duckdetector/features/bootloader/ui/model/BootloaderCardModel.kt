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

package com.eltavine.duckdetector.features.bootloader.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

enum class BootloaderCardAssessment {
    AUTHORITATIVE,
    CONSISTENCY_REVIEW,
    CONSISTENCY_CONFLICT,
}

data class BootloaderCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val assessment: BootloaderCardAssessment,
    val verdict: String,
    val summary: String,
    val headerFacts: List<BootloaderHeaderFactModel>,
    val stateRows: List<BootloaderDetailRowModel>,
    val attestationRows: List<BootloaderDetailRowModel>,
    val propertyRows: List<BootloaderDetailRowModel>,
    val consistencyRows: List<BootloaderDetailRowModel>,
    val impactItems: List<BootloaderImpactItemModel>,
    val methodRows: List<BootloaderDetailRowModel>,
    val scanRows: List<BootloaderDetailRowModel>,
) {
    val showConsistencyQuestionIcon: Boolean
        get() = assessment != BootloaderCardAssessment.AUTHORITATIVE

    val assessmentStatus: DetectorStatus?
        get() = when (assessment) {
            BootloaderCardAssessment.AUTHORITATIVE -> null
            BootloaderCardAssessment.CONSISTENCY_REVIEW -> DetectorStatus.warning()
            BootloaderCardAssessment.CONSISTENCY_CONFLICT -> DetectorStatus.danger()
        }
}

data class BootloaderHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class BootloaderDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class BootloaderImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
