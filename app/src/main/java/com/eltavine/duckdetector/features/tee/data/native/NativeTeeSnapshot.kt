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

package com.eltavine.duckdetector.features.tee.data.native

data class NativeTeeSnapshot(
    val tracingDetected: Boolean = false,
    val suspiciousMappings: List<String> = emptyList(),
    val trickyStoreDetected: Boolean = false,
    val gotHookDetected: Boolean = false,
    val syscallMismatchDetected: Boolean = false,
    val inlineHookDetected: Boolean = false,
    val honeypotDetected: Boolean = false,
    val trickyStoreMethods: List<String> = emptyList(),
    val trickyStoreDetails: String = "Native probe unavailable",
    val leafDerPrimaryDetected: Boolean = false,
    val leafDerSecondaryDetected: Boolean = false,
    val leafDerFindings: List<String> = emptyList(),
    val pageSize: Int? = null,
    val timingSummary: String? = null,
    val trickyStoreTimerSource: String = "unknown",
    val trickyStoreTimerFallbackReason: String? = null,
    val trickyStoreAffinityStatus: String = "not_requested",
    val trickyStoreTimingRunCount: Int? = null,
    val trickyStoreTimingSuspiciousRunCount: Int? = null,
    val trickyStoreTimingMedianGapNs: Long? = null,
    val trickyStoreTimingGapMadNs: Long? = null,
    val trickyStoreTimingMedianNoiseFloorNs: Long? = null,
    val trickyStoreTimingMedianRatioPercent: Int? = null,
)
