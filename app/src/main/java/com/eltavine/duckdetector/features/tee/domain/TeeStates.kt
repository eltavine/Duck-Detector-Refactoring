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

package com.eltavine.duckdetector.features.tee.domain

enum class TeeTrustRoot {
    UNKNOWN,
    FACTORY,
    GOOGLE,
    GOOGLE_RKP,
    AOSP,
}

enum class TeePatchGrade {
    UNKNOWN,
    MATCHED,
    WARNING,
    SUSPICIOUS,
}

enum class TeeNetworkMode {
    INACTIVE,
    CONSENT_REQUIRED,
    ACTIVE,
    SKIPPED,
    ERROR,
}

data class TeeRkpState(
    val provisioned: Boolean = false,
    val serverSigned: Boolean = false,
    val validityDays: Int? = null,
    val validatedEntity: String? = null,
    val attestationExtensionCount: Int = 0,
    val consistencyIssue: String? = null,
    val abuseLevel: TeeSignalLevel = TeeSignalLevel.INFO,
    val abuseSummary: String? = null,
)

data class TeePatchState(
    val systemPatchLevel: String? = null,
    val teePatchLevel: String? = null,
    val vendorPatchLevel: String? = null,
    val bootPatchLevel: String? = null,
    val grade: TeePatchGrade = TeePatchGrade.UNKNOWN,
    val summary: String = "Patch data unavailable",
)

data class TeeSoterState(
    val serviceReachable: Boolean = false,
    val keyPrepared: Boolean = false,
    val signSessionAvailable: Boolean = false,
    val available: Boolean = false,
    val damaged: Boolean = false,
    val abnormalEnvironment: Boolean = false,
    val summary: String = "Soter check skipped",
)

data class TeeNetworkState(
    val mode: TeeNetworkMode = TeeNetworkMode.INACTIVE,
    val summary: String = "Offline-only verification",
    val detail: String? = null,
    val cacheEntries: Int = 0,
    val cacheAgeHours: Long? = null,
    val usedCache: Boolean = false,
    val usingCacheFallback: Boolean = false,
)
