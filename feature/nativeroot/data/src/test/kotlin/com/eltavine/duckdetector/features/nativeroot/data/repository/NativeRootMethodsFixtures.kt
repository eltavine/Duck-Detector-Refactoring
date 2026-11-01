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

package com.eltavine.duckdetector.features.nativeroot.data.repository

import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.features.nativeroot.data.native.NativeRootNativeSnapshot
import com.eltavine.duckdetector.features.nativeroot.data.probes.CgroupProcessLeakProbeResult
import com.eltavine.duckdetector.features.nativeroot.data.probes.KernelSuManagerFingerprintProbeResult
import com.eltavine.duckdetector.features.nativeroot.data.probes.KernelSuThroneHuntProbeResult
import com.eltavine.duckdetector.features.nativeroot.data.probes.MountNamespaceDriftProbeResult
import com.eltavine.duckdetector.features.nativeroot.data.probes.TempRootArtifactProbeResult
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodResult

/** The method row named [label], with the remaining Kotlin-side probes left unavailable. */
internal fun methodRow(
    snapshot: NativeRootNativeSnapshot,
    label: String,
    throneHuntResult: KernelSuThroneHuntProbeResult = KernelSuThroneHuntProbeResult(
        available = false,
        watchInstalled = false,
        watchDenied = false,
        packageDirectory = "",
        watchDescriptor = -1,
        directoryOpenCount = 0,
        directoryAccessCount = 0,
        rawEventCount = 0,
        invalidEventCount = 0,
        baselineHitCount = 0,
        stimulusDetail = "",
        findings = emptyList(),
        detail = "",
    ),
): NativeRootMethodResult = buildMethods(
    snapshot = snapshot,
    findings = throneHuntResult.findings,
    shellTmpDetail = "",
    rootProcessDetail = "",
    cgroupResult = CgroupProcessLeakProbeResult(false, 0, 0, 0, 0, emptyList(), ""),
    mountNamespaceResult = MountNamespaceDriftProbeResult(false, false, "", "", 0, emptyList(), ""),
    managerFingerprintResult = KernelSuManagerFingerprintProbeResult(
        false,
        InstalledPackageVisibility.UNKNOWN,
        false,
        0,
        emptyList(),
        "",
    ),
    tempRootArtifactResult = TempRootArtifactProbeResult(false, 0, emptyList(), false, false, ""),
    throneHuntResult = throneHuntResult,
).single { it.label == label }
