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

package com.eltavine.duckdetector.features.kernelcheck.data.native

import com.eltavine.duckdetector.core.native.NativeCollectionStatus

data class KernelCheckNativeSnapshot(
    val available: Boolean = false,
    val procVersion: String = "",
    val procCmdline: String = "",
    val utsRelease: String = "",
    val utsVersion: String = "",
    val sysctlOsRelease: String = "",
    val sysctlVersion: String = "",
    val suspiciousCmdline: Boolean = false,
    val kptrExposed: Boolean = false,
    val findings: List<String> = emptyList(),
    val cpuIdentityStatus: Arm64CpuIdentityProbeStatus = Arm64CpuIdentityProbeStatus.UNKNOWN,
    val cpuIdentityObservations: List<Arm64CpuIdentityObservation> = emptyList(),
    /**
     * Why this snapshot is or is not usable. [available] alone cannot distinguish "the probe ran and
     * found nothing" from "the probe never ran", so the reason is carried here.
     */
    val collection: NativeCollectionStatus = NativeCollectionStatus.Collected,
)
