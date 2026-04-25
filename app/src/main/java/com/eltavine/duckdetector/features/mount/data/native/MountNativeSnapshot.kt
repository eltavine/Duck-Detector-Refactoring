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

package com.eltavine.duckdetector.features.mount.data.native

data class MountNativeFinding(
    val group: String,
    val severity: String,
    val label: String,
    val value: String,
    val detail: String,
)

data class MountNativeSnapshot(
    val available: Boolean = false,
    val mountsReadable: Boolean = false,
    val mountInfoReadable: Boolean = false,
    val mapsReadable: Boolean = false,
    val filesystemsReadable: Boolean = false,
    val initNamespaceReadable: Boolean = false,
    val statxSupported: Boolean = false,
    val permissionTotal: Int = 0,
    val permissionDenied: Int = 0,
    val permissionAccessible: Int = 0,
    val mountEntryCount: Int = 0,
    val mountInfoEntryCount: Int = 0,
    val mapLineCount: Int = 0,
    val busyboxDetected: Boolean = false,
    val magiskMountDetected: Boolean = false,
    val zygiskCacheDetected: Boolean = false,
    val systemRwDetected: Boolean = false,
    val overlayMountDetected: Boolean = false,
    val namespaceAnomalyDetected: Boolean = false,
    val dataAdbDetected: Boolean = false,
    val debugRamdiskDetected: Boolean = false,
    val hybridMountDetected: Boolean = false,
    val metaHybridMountDetected: Boolean = false,
    val suspiciousTmpfsDetected: Boolean = false,
    val ksuOverlayDetected: Boolean = false,
    val loopDeviceDetected: Boolean = false,
    val dmVerityBypassDetected: Boolean = false,
    val mountPropagationAnomaly: Boolean = false,
    val inconsistentMountDetected: Boolean = false,
    val mountIdLoopholeDetected: Boolean = false,
    val peerGroupLoopholeDetected: Boolean = false,
    val minorDevLoopholeDetected: Boolean = false,
    val futileHideDetected: Boolean = false,
    val statxMntIdMismatch: Boolean = false,
    val bindMountDetected: Boolean = false,
    val mountOptionsAnomaly: Boolean = false,
    val statxMountRootAnomaly: Boolean = false,
    val overlayfsKernelSupport: Boolean = false,
    val systemFsTypeAnomaly: Boolean = false,
    val tmpfsSizeAnomaly: Boolean = false,
    val findings: List<MountNativeFinding> = emptyList(),
)
