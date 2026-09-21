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

package com.eltavine.duckdetector.features.selinux.data.native

import com.eltavine.duckdetector.core.native.NativeCollectionStatus

data class SelinuxNativeAuditSnapshot(
    val available: Boolean = false,
    val callbackInstalled: Boolean = false,
    val probeRan: Boolean = false,
    val denialObserved: Boolean = false,
    val allowObserved: Boolean = false,
    val probeMarker: String? = null,
    val failureReason: String? = null,
    val callbackLines: List<String> = emptyList(),
    /**
     * Why this snapshot is or is not usable. [available] alone cannot distinguish "the probe ran and
     * found nothing" from "the probe never ran", so the reason is carried here. [failureReason] holds
     * the same information in the wording the report shows.
     */
    val collection: NativeCollectionStatus = NativeCollectionStatus.Collected,
)
