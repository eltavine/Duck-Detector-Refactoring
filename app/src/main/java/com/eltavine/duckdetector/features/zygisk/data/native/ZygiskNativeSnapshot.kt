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

package com.eltavine.duckdetector.features.zygisk.data.native

data class ZygiskNativeTrace(
    val group: String,
    val severity: String,
    val label: String,
    val detail: String,
)

data class ZygiskNativeSnapshot(
    val available: Boolean = false,
    val heapAvailable: Boolean = false,
    val seccompSupported: Boolean = false,
    val tracerPid: Int = 0,
    val strongHitCount: Int = 0,
    val heuristicHitCount: Int = 0,
    val solistHitCount: Int = 0,
    val vmapHitCount: Int = 0,
    val atexitHitCount: Int = 0,
    val smapsHitCount: Int = 0,
    val namespaceHitCount: Int = 0,
    val linkerHookHitCount: Int = 0,
    val stackLeakHitCount: Int = 0,
    val seccompHitCount: Int = 0,
    val heapHitCount: Int = 0,
    val threadHitCount: Int = 0,
    val fdHitCount: Int = 0,
    val traces: List<ZygiskNativeTrace> = emptyList(),
)
