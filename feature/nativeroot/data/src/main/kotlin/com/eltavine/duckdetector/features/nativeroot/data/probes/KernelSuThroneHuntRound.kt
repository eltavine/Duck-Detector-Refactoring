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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import android.content.Context
import com.eltavine.duckdetector.core.native.NativeCollectionOutcome
import com.eltavine.duckdetector.core.native.NativeCollectionStatus
import com.eltavine.duckdetector.features.nativeroot.data.service.ThroneHuntCarrierManager
import kotlinx.coroutines.delay

// Validates the inherited app_zygote watch, drains baseline activity, applies the package-settings
// stimulus, waits through the observation window and collects directory activity without accessor
// attribution. Neither counts nor timing establish that a KernelSU manager scan ran.
class KernelSuThroneHuntRound(
    context: Context? = null,
    private val carrierManager: ThroneHuntCarrierManager = ThroneHuntCarrierManager(
        context?.applicationContext
    ),
    private val stimulus: ThroneHuntStimulus = ThroneHuntStimulus(),
) {

    private val appContext = context?.applicationContext

    // [scanStartedAt] is the Native Root scan's start on the SystemClock.elapsedRealtime clock.
    suspend fun run(scanStartedAt: Long): KernelSuThroneHuntRoundResult {
        try {
            val context = appContext ?: return KernelSuThroneHuntRoundResult(
                available = false,
                collection = NativeCollectionStatus.failed(
                    NativeCollectionOutcome.BRIDGE_FAILED,
                    IllegalStateException("Context unavailable."),
                ),
                failureStage = "CONTEXT_UNAVAILABLE",
                stimulusApplied = false,
                detail = "Context unavailable.",
            )

            val carrierState = carrierManager.collectSnapshot(scanStartedAt)
            if (!carrierState.collection.isTrustworthy) {
                return KernelSuThroneHuntRoundResult(
                    available = false,
                    collection = carrierState.collection,
                    failureStage = "CARRIER_SETUP_FAILED",
                    stimulusApplied = false,
                    watchDenied = carrierState.watchDenied,
                    packageDirectory = carrierState.packageDirectory,
                    watchDescriptor = carrierState.watchDescriptor,
                    detail = carrierState.collection.explain(
                        "Throne hunt carrier collection failed",
                    ),
                )
            }

            if (!carrierState.watchInstalled) {
                return KernelSuThroneHuntRoundResult(
                    available = false,
                    collection = NativeCollectionStatus.Collected,
                    failureStage = "WATCH_NOT_INSTALLED",
                    stimulusApplied = false,
                    watchDenied = carrierState.watchDenied,
                    packageDirectory = carrierState.packageDirectory,
                    watchDescriptor = carrierState.watchDescriptor,
                    detail = carrierState.failureReason
                        ?: "The app_zygote package directory watch was not installed.",
                )
            }

            // Discard pre-stimulus activity collected since preload. Activity in the remaining
            // window can still be unrelated to the stimulus; draining does not establish causality.
            val baseline = carrierManager.drainEvents(scanStartedAt)
            if (!baseline.collection.isTrustworthy) {
                return KernelSuThroneHuntRoundResult(
                    available = false,
                    collection = baseline.collection,
                    failureStage = "BASELINE_DRAIN_FAILED",
                    stimulusApplied = false,
                    watchDenied = carrierState.watchDenied,
                    packageDirectory = carrierState.packageDirectory,
                    watchDescriptor = carrierState.watchDescriptor,
                    detail = baseline.collection.explain("Baseline event drain failed"),
                )
            }
            val baselineHitCount = baseline.directoryOpenCount + baseline.directoryAccessCount

            val outcome = stimulus.apply(context)
            if (!outcome.applied) {
                // Without a confirmed stimulus there is no controlled observation window. Draining
                // again would let an unrelated packages.list rewrite masquerade as this probe.
                // 刺激未确认时不存在受控观察窗口；继续 drain 会让无关 packages.list 重写
                // 冒充本探针的结果。
                return KernelSuThroneHuntRoundResult(
                    available = false,
                    collection = NativeCollectionStatus.Collected,
                    failureStage = "STIMULUS_FAILED",
                    stimulusApplied = false,
                    watchDenied = carrierState.watchDenied,
                    packageDirectory = carrierState.packageDirectory,
                    watchDescriptor = carrierState.watchDescriptor,
                    baselineHitCount = baselineHitCount,
                    stimulusDetail = outcome.detail,
                    detail = buildString {
                        append("watchInstalled=true")
                        append("\nstimulusApplied=false")
                        append("\nstimulus=")
                        append(outcome.detail)
                        append("\nbaselineHits=")
                        append(baselineHitCount)
                    },
                )
            }

            delay(ThroneHuntStimulus.SETTINGS_WRITE_WINDOW_MS)

        // Drained after the wait so the event stream covers the full stimulus window rather than
        // the moment before the settings write landed.
            val observed = carrierManager.drainEvents(scanStartedAt)
            if (!observed.collection.isTrustworthy || !observed.watchInstalled) {
                return KernelSuThroneHuntRoundResult(
                    available = false,
                    collection = observed.collection,
                    failureStage = "FINAL_DRAIN_FAILED",
                    stimulusApplied = true,
                    watchDenied = observed.watchDenied || carrierState.watchDenied,
                    packageDirectory = observed.packageDirectory,
                    watchDescriptor = observed.watchDescriptor,
                    baselineHitCount = baselineHitCount,
                    stimulusDetail = outcome.detail,
                    detail = observed.failureReason
                        ?: observed.collection.explain("Throne hunt event drain failed"),
                )
            }

            return KernelSuThroneHuntRoundResult(
                available = true,
                collection = observed.collection,
                failureStage = "READY",
                stimulusApplied = true,
                watchDenied = observed.watchDenied,
                packageDirectory = observed.packageDirectory,
                watchDescriptor = observed.watchDescriptor,
                directoryOpenCount = observed.directoryOpenCount,
                directoryAccessCount = observed.directoryAccessCount,
                rawEventCount = observed.rawEventCount,
                invalidEventCount = observed.invalidEventCount,
                baselineHitCount = baselineHitCount,
                stimulusDetail = outcome.detail,
                detail = buildString {
                    append("watchInstalled=true")
                    append("\nstimulusApplied=true")
                    append("\nstimulus=")
                    append(outcome.detail)
                    append("\nbaselineHits=")
                    append(baselineHitCount)
                    if (observed.failureReason != null) {
                        append("\nfailure=")
                        append(observed.failureReason)
                    }
                },
            )
        } finally {
            carrierManager.close()
        }
    }
}

data class KernelSuThroneHuntRoundResult(
    val available: Boolean,
    val collection: NativeCollectionStatus = NativeCollectionStatus.Collected,
    val failureStage: String = "READY",
    val stimulusApplied: Boolean = false,
    val watchDenied: Boolean = false,
    val packageDirectory: String = "",
    val watchDescriptor: Int = -1,
    val directoryOpenCount: Int = 0,
    val directoryAccessCount: Int = 0,
    val rawEventCount: Int = 0,
    val invalidEventCount: Int = 0,
    val baselineHitCount: Int = 0,
    val stimulusDetail: String = "",
    val detail: String,
)
