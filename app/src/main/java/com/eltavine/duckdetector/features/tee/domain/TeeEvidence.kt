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

package com.eltavine.duckdetector.features.tee.domain

data class TeeEvidenceItem(
    val title: String,
    val body: String,
    val level: TeeSignalLevel,
    // 这是隐藏交互使用的原始复制文本；默认不展示在 UI 上，只在特定行位通过手势导出给人工审查。
    // Raw copy text for hidden interaction; it stays out of the visible UI and is only exported from specific rows through a gesture.
    val hiddenCopyText: String? = null,
)

data class TeeEvidenceSection(
    val title: String,
    val items: List<TeeEvidenceItem>,
)
