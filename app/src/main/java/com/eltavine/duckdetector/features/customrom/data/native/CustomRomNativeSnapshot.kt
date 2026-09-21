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

package com.eltavine.duckdetector.features.customrom.data.native

import com.eltavine.duckdetector.core.native.NativeCollectionStatus
import com.eltavine.duckdetector.features.customrom.domain.CustomRomFinding
import com.eltavine.duckdetector.features.customrom.domain.CustomRomModificationFinding

data class CustomRomNativeSnapshot(
    val available: Boolean = false,
    val propertyAreaAvailable: Boolean = false,
    val propertyAreaContextCount: Int = 0,
    val propertyAreaAnomalyCount: Int = 0,
    val propertyAreaItemCount: Int = 0,
    val symbolScanAvailable: Boolean = false,
    val platformFiles: List<CustomRomFinding> = emptyList(),
    val modificationFindings: List<CustomRomModificationFinding> = emptyList(),
    val resourceInjectionFindings: List<CustomRomFinding> = emptyList(),
    val recoveryScripts: List<String> = emptyList(),
    val policyFindings: List<CustomRomFinding> = emptyList(),
    val overlayFindings: List<CustomRomFinding> = emptyList(),
    val symbolFindings: List<CustomRomFinding> = emptyList(),
    /**
     * Why this snapshot is or is not usable. [available] alone cannot distinguish "the probe ran and
     * found nothing" from "the probe never ran", so the reason is carried here.
     */
    val collection: NativeCollectionStatus = NativeCollectionStatus.Collected,
) {
    val propertyAreaItemAnomalyCount: Int
        get() = propertyAreaItemCount
}
