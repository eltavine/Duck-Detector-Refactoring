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

package com.eltavine.duckdetector.features.lsposed.data.native

data class LSPosedNativeTrace(
    val group: String,
    val severity: String,
    val label: String,
    val detail: String,
)

data class LSPosedNativeSnapshot(
    val available: Boolean = false,
    val heapAvailable: Boolean = false,
    val mapsHitCount: Int = 0,
    val mapsScannedLines: Int = 0,
    val heapHitCount: Int = 0,
    val heapScannedRegions: Int = 0,
    val traces: List<LSPosedNativeTrace> = emptyList(),
)
