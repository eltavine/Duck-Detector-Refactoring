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

package com.eltavine.duckdetector.sdk

import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.features.adbruntime.detector.AdbRuntimeDetector
import com.eltavine.duckdetector.features.bootloader.detector.BootloaderDetector
import com.eltavine.duckdetector.features.customrom.detector.CustomRomDetector
import com.eltavine.duckdetector.features.dangerousapps.detector.DangerousAppsDetector
import com.eltavine.duckdetector.features.kernelcheck.detector.KernelCheckDetector
import com.eltavine.duckdetector.features.lsposed.detector.LSPosedDetector
import com.eltavine.duckdetector.features.memory.detector.MemoryDetector
import com.eltavine.duckdetector.features.mount.detector.MountDetector
import com.eltavine.duckdetector.features.nativeroot.detector.NativeRootDetector
import com.eltavine.duckdetector.features.playintegrityfix.detector.PlayIntegrityFixDetector
import com.eltavine.duckdetector.features.selinux.detector.SelinuxDetector
import com.eltavine.duckdetector.features.su.detector.SuDetector
import com.eltavine.duckdetector.features.systemproperties.detector.SystemPropertiesDetector
import com.eltavine.duckdetector.features.tee.detector.TeeDetector
import com.eltavine.duckdetector.features.virtualization.detector.VirtualizationDetector
import com.eltavine.duckdetector.features.zygisk.detector.ZygiskDetector

/**
 * Every detector, in the order their scans start.
 *
 * This is the one list of detectors: the SDK scans in this order, and the application starts its
 * dashboard sessions in this order. Bootloader and TEE start first, as the application has always
 * started them; every other detector follows by name. Adding a detector means adding it here and
 * giving it a dashboard card.
 */
public object DetectorCatalog {
    public val all: List<Detector<*, *>> = listOf(
        BootloaderDetector,
        TeeDetector,
        AdbRuntimeDetector,
        CustomRomDetector,
        DangerousAppsDetector,
        KernelCheckDetector,
        LSPosedDetector,
        MemoryDetector,
        MountDetector,
        NativeRootDetector,
        PlayIntegrityFixDetector,
        SelinuxDetector,
        SuDetector,
        SystemPropertiesDetector,
        VirtualizationDetector,
        ZygiskDetector,
    )
}
