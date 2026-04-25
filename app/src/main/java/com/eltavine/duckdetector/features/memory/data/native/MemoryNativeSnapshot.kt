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

package com.eltavine.duckdetector.features.memory.data.native

data class MemoryNativeFinding(
    val section: String,
    val category: String,
    val label: String,
    val severity: String,
    val detail: String,
)

data class MemoryNativeSnapshot(
    val available: Boolean = false,
    val gotPltHook: Boolean = false,
    val inlineHook: Boolean = false,
    val prologueModified: Boolean = false,
    val trampoline: Boolean = false,
    val suspiciousJump: Boolean = false,
    val modifiedFunctionCount: Int = 0,
    val writableExec: Boolean = false,
    val anonymousExec: Boolean = false,
    val swappedExec: Boolean = false,
    val sharedDirtyExec: Boolean = false,
    val deletedSo: Boolean = false,
    val suspiciousMemfd: Boolean = false,
    val execAshmem: Boolean = false,
    val devZeroExec: Boolean = false,
    val signalHandler: Boolean = false,
    val fridaSignal: Boolean = false,
    val anonymousSignal: Boolean = false,
    val vdsoRemapped: Boolean = false,
    val vdsoUnusualBase: Boolean = false,
    val deletedLibrary: Boolean = false,
    val hiddenModule: Boolean = false,
    val mapsOnlyModule: Boolean = false,
    val criticalCount: Int = 0,
    val highCount: Int = 0,
    val mediumCount: Int = 0,
    val lowCount: Int = 0,
    val findings: List<MemoryNativeFinding> = emptyList(),
)
