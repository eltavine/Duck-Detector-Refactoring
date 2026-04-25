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

package com.eltavine.duckdetector.features.customrom.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class CustomRomCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<CustomRomHeaderFactModel>,
    val buildRows: List<CustomRomDetailRowModel>,
    val runtimeRows: List<CustomRomDetailRowModel>,
    val frameworkRows: List<CustomRomDetailRowModel>,
    val impactItems: List<CustomRomImpactItemModel>,
    val methodRows: List<CustomRomDetailRowModel>,
    val scanRows: List<CustomRomDetailRowModel>,
)

data class CustomRomHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class CustomRomDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class CustomRomImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
