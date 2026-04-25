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

package com.eltavine.duckdetector.features.memory.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class MemoryCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<MemoryHeaderFactModel>,
    val hookRows: List<MemoryDetailRowModel>,
    val mappingRows: List<MemoryDetailRowModel>,
    val loaderRows: List<MemoryDetailRowModel>,
    val impactItems: List<MemoryImpactItemModel>,
    val methodRows: List<MemoryDetailRowModel>,
    val scanRows: List<MemoryDetailRowModel>,
)

data class MemoryHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class MemoryDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class MemoryImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
