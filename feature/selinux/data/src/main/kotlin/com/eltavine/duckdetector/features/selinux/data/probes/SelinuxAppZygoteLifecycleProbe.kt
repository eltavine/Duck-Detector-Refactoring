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

package com.eltavine.duckdetector.features.selinux.data.probes

import android.content.Context
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxContextValidityCarrierManager
import com.eltavine.duckdetector.core.evidence.ScanEpoch

/** Feature-owned projection of App-Zygote lifecycle evidence for integration diagnostics. */
data class SelinuxAppZygoteLifecycleObservation(
    val available: Boolean,
    val failureReason: String?,
    val appZygoteParentPid: Int?,
    val preloadStartedNanos: Long?,
    val preloadVersionCode: Long?,
    val preloadBuildRevision: String?,
)

/**
 * Keeps app-level instrumentation on the feature boundary instead of making the composition root
 * depend directly on the SELinux-policy capability implementation.
 */
class SelinuxAppZygoteLifecycleProbe(context: Context) {
    private val carrier = SelinuxContextValidityCarrierManager(context.applicationContext)

    suspend fun collect(scanStartedNanos: Long): SelinuxAppZygoteLifecycleObservation {
        val snapshot = carrier.collectSnapshot(ScanEpoch.begin(scanStartedNanos))
        return SelinuxAppZygoteLifecycleObservation(
            available = snapshot.available,
            failureReason = snapshot.failureReason,
            appZygoteParentPid = snapshot.appZygoteParentPid,
            preloadStartedNanos = snapshot.appZygotePreloadStartedNanos,
            preloadVersionCode = snapshot.appZygotePreloadVersionCode,
            preloadBuildRevision = snapshot.appZygotePreloadBuildRevision,
        )
    }
}
