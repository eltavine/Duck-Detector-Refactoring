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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import android.content.Context
import com.eltavine.duckdetector.features.nativeroot.data.service.ThroneHuntCarrierManager
import kotlinx.coroutines.delay

// Runs one full oracle round: validates the inherited app_zygote watch, drains whatever the watch
// collected before the stimulus, applies the zero-permission packages.list rewrite, waits out the
// Settings coalescing window, then consumes the event stream to see what the KernelSU throne hunt
// did to our package directory in between.
class KernelSuThroneHuntRound(
    context: Context? = null,
    private val carrierManager: ThroneHuntCarrierManager = ThroneHuntCarrierManager(
        context?.applicationContext
    ),
    private val stimulus: ThroneHuntStimulus = ThroneHuntStimulus,
) {

    private val appContext = context?.applicationContext

    suspend fun run(): KernelSuThroneHuntRoundResult {
        val context = appContext ?: return KernelSuThroneHuntRoundResult(
            available = false,
            stimulusApplied = false,
            detail = "Context unavailable.",
        )

        val carrierState = carrierManager.collectSnapshot()
        if (!carrierState.watchInstalled) {
            return KernelSuThroneHuntRoundResult(
                available = false,
                stimulusApplied = false,
                watchDenied = carrierState.watchDenied,
                packageDirectory = carrierState.packageDirectory,
                detail = carrierState.failureReason
                    ?: "The app_zygote package directory watch was not installed.",
            )
        }

        // Baseline. The watch starts collecting at app_zygote preload, so the stream already holds
        // everything that happened before the stimulus - our own startup noise, or an unrelated
        // packages.list rewrite that kicked off a hunt of its own. Draining it here means the final
        // drain covers the stimulus window only, and none of that can be read as our result.
        val baseline = carrierManager.drainEvents()
        val baselineHitCount = baseline.directoryOpenCount + baseline.directoryAccessCount

        val outcome = stimulus.apply(context)
        if (outcome.applied) {
            delay(ThroneHuntStimulus.SETTINGS_WRITE_WINDOW_MS)
        }

        // Drained after the wait so the event stream covers the full stimulus window rather than
        // the moment before the settings write landed.
        val observed = carrierManager.drainEvents()
        return KernelSuThroneHuntRoundResult(
            available = observed.watchInstalled,
            stimulusApplied = outcome.applied,
            watchDenied = observed.watchDenied,
            packageDirectory = observed.packageDirectory,
            watchDescriptor = observed.watchDescriptor,
            directoryOpenCount = observed.directoryOpenCount,
            directoryAccessCount = observed.directoryAccessCount,
            baselineHitCount = baselineHitCount,
            detail = buildString {
                append("watchInstalled=")
                append(observed.watchInstalled)
                append("\nstimulusApplied=")
                append(outcome.applied)
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
    }
}

data class KernelSuThroneHuntRoundResult(
    val available: Boolean,
    val stimulusApplied: Boolean,
    val watchDenied: Boolean = false,
    val packageDirectory: String = "",
    val watchDescriptor: Int = -1,
    val directoryOpenCount: Int = 0,
    val directoryAccessCount: Int = 0,
    val baselineHitCount: Int = 0,
    val detail: String,
)
