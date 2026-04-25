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

package com.eltavine.duckdetector.features.playintegrityfix.data.native

data class PlayIntegrityFixNativeTrace(
    val severity: String,
    val label: String,
    val detail: String,
)

data class PlayIntegrityFixNativeSnapshot(
    val available: Boolean = false,
    val nativeProperties: Map<String, String> = emptyMap(),
    val runtimeTraces: List<PlayIntegrityFixNativeTrace> = emptyList(),
) {
    val nativePropertyHitCount: Int
        get() = nativeProperties.values.count { it.isNotBlank() }
}
