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

package com.eltavine.duckdetector.features.nativeroot.data.native

data class NativeRootNativeFinding(
    val group: String,
    val severity: String,
    val label: String,
    val value: String,
    val detail: String,
)

data class NativeRootNativeSnapshot(
    val available: Boolean = false,
    val kernelSuDetected: Boolean = false,
    val aPatchDetected: Boolean = false,
    val magiskDetected: Boolean = false,
    val susfsDetected: Boolean = false,
    val kernelSuVersion: Long = 0L,
    val prctlProbeHit: Boolean = false,
    val ksuSupercallAttempted: Boolean = false,
    val ksuSupercallProbeHit: Boolean = false,
    val ksuSupercallBlocked: Boolean = false,
    val ksuSupercallSafeMode: Boolean = false,
    val ksuSupercallLkm: Boolean = false,
    val ksuSupercallLateLoad: Boolean = false,
    val ksuSupercallPrBuild: Boolean = false,
    val ksuSupercallManager: Boolean = false,
    val susfsProbeHit: Boolean = false,
    val selfSuDomain: Boolean = false,
    val selfContext: String = "",
    val selfKsuDriverFdCount: Int = 0,
    val selfKsuFdwrapperFdCount: Int = 0,
    val pathHitCount: Int = 0,
    val pathCheckCount: Int = 0,
    val processHitCount: Int = 0,
    val processCheckedCount: Int = 0,
    val processDeniedCount: Int = 0,
    val kernelHitCount: Int = 0,
    val kernelSourceCount: Int = 0,
    val propertyHitCount: Int = 0,
    val propertyCheckCount: Int = 0,
    val findings: List<NativeRootNativeFinding> = emptyList(),
)
