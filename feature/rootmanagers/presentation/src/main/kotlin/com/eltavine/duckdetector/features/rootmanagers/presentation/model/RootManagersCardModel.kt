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

package com.eltavine.duckdetector.features.rootmanagers.presentation.model

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.report.DetectorHeadline

data class RootManagersCardModel(
    override val title: String,
    val subtitle: String,
    override val status: DetectorStatus,
    override val verdict: String,
    override val summary: String,
    val entryRows: List<RootManagersDetailRowModel>,
    val profileRows: List<RootManagersDetailRowModel>,
    val scanRows: List<RootManagersDetailRowModel>,
    val headerFacts: List<RootManagersDetailRowModel> = emptyList(),
    val impactRows: List<RootManagersDetailRowModel> = emptyList(),
    val methodRows: List<RootManagersDetailRowModel> = emptyList(),
) : DetectorHeadline

data class RootManagersDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
    /** Full node detail copied on a double tap; null when the row has nothing more to share. */
    val hiddenCopyText: String? = null,
)
