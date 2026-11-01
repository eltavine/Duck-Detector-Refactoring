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

import com.eltavine.duckdetector.core.native.NativeCollectionStatus
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding

data class KernelSuThroneHuntProbeResult(
    val available: Boolean,
    val collection: NativeCollectionStatus = NativeCollectionStatus.Collected,
    val failureStage: String = "READY",
    val watchInstalled: Boolean,
    val watchDenied: Boolean,
    val packageDirectory: String,
    val watchDescriptor: Int,
    val directoryOpenCount: Int,
    val directoryAccessCount: Int,
    val rawEventCount: Int,
    val invalidEventCount: Int,
    val baselineHitCount: Int,
    val stimulusDetail: String,
    val findings: List<NativeRootFinding>,
    val detail: String,
) {
    val hitCount: Int
        get() = directoryOpenCount + directoryAccessCount
}

// inotify_event carries no accessor PID/UID, so counts cannot identify a manager scan.
// ACK android15-6.6 fsnotify_file() also suppresses file notifications for FMODE_NONOTIFY,
// as used by SukiSU's manager scanner. See the pinned references in feature/nativeroot/EVIDENCE.md.
// Keep the already-consumed round as diagnostic data only, including zero-event rounds.
class KernelSuThroneHuntProbe {

    fun run(round: KernelSuThroneHuntRoundResult): KernelSuThroneHuntProbeResult {
        if (!round.available) {
            // Preserve every diagnostic even when the verdict is unavailable. Collapsing counters
            // to zero here would hide exactly the layer that failed on a device.
            // 即使结论 unavailable 也保留所有诊断；把计数清零会隐藏设备上真正失败的层。
            return KernelSuThroneHuntProbeResult(
                available = false,
                collection = round.collection,
                failureStage = round.failureStage,
                watchInstalled = round.failureStage == "STIMULUS_FAILED",
                watchDenied = round.watchDenied,
                packageDirectory = round.packageDirectory,
                watchDescriptor = round.watchDescriptor,
                directoryOpenCount = round.directoryOpenCount,
                directoryAccessCount = round.directoryAccessCount,
                rawEventCount = round.rawEventCount,
                invalidEventCount = round.invalidEventCount,
                baselineHitCount = round.baselineHitCount,
                stimulusDetail = round.stimulusDetail,
                findings = emptyList(),
                detail = round.detail,
            )
        }

        val detail = buildString {
            append("packageDir=")
            append(round.packageDirectory)
            append("\nwatchDescriptor=")
            append(round.watchDescriptor)
            append("\ndirectoryOpen=")
            append(round.directoryOpenCount)
            append("\ndirectoryAccess=")
            append(round.directoryAccessCount)
            append("\nrawEvents=")
            append(round.rawEventCount)
            append("\ninvalidEvents=")
            append(round.invalidEventCount)
            append("\nbaselineHits=")
            append(round.baselineHitCount)
            append('\n')
            append(round.detail)
        }

        return KernelSuThroneHuntProbeResult(
            available = true,
            collection = round.collection,
            failureStage = round.failureStage,
            watchInstalled = true,
            watchDenied = round.watchDenied,
            packageDirectory = round.packageDirectory,
            watchDescriptor = round.watchDescriptor,
            directoryOpenCount = round.directoryOpenCount,
            directoryAccessCount = round.directoryAccessCount,
            rawEventCount = round.rawEventCount,
            invalidEventCount = round.invalidEventCount,
            baselineHitCount = round.baselineHitCount,
            stimulusDetail = round.stimulusDetail,
            findings = emptyList(),
            detail = detail,
        )
    }
}
