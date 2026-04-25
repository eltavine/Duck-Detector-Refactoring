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

package com.eltavine.duckdetector.features.virtualization.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class VirtualizationCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<VirtualizationHeaderFactModel>,
    val environmentRows: List<VirtualizationDetailRowModel>,
    val runtimeRows: List<VirtualizationDetailRowModel>,
    val consistencyRows: List<VirtualizationDetailRowModel>,
    val honeypotRows: List<VirtualizationDetailRowModel>,
    val hostAppRows: List<VirtualizationDetailRowModel>,
    val impactItems: List<VirtualizationImpactItemModel>,
    val methodRows: List<VirtualizationDetailRowModel>,
    val scanRows: List<VirtualizationDetailRowModel>,
    val references: List<String>,
)

data class VirtualizationHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class VirtualizationDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class VirtualizationImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
