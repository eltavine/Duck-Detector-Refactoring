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

data class MetricChipModel(
    val label: String,
    val value: String,
    val status: DetectorStatus = DetectorStatus.allClear(),
)

data class HighlightItemModel(
    val title: String,
    val detail: String,
    val status: DetectorStatus,
)

data class ContextItemModel(
    val label: String,
    val value: String,
)

data class ActionItemModel(
    val label: String,
    val counter: String? = null,
)
