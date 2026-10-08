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

package com.eltavine.duckdetector.features.nativeroot.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingObservation
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingVerdict
import com.eltavine.duckdetector.features.nativeroot.presentation.model.NativeRootDetailRowModel

internal fun srcuTimingRow(observation: SrcuTimingObservation): NativeRootDetailRowModel {
    val analysis = observation.analysis
    val value = when (observation.collection) {
        SrcuTimingCollection.NOT_REQUESTED -> "Not requested"
        SrcuTimingCollection.UNSUPPORTED_ANDROID -> "Unsupported Android trigger"
        SrcuTimingCollection.UNSUPPORTED_KERNEL -> "Unsupported kernel"
        SrcuTimingCollection.COLLECTED -> when (analysis.verdict) {
            SrcuTimingVerdict.REPEATABLE_DELAY -> "Repeatable delay (experimental)"
            SrcuTimingVerdict.NOT_OBSERVED -> "Delay not observed"
            SrcuTimingVerdict.INCONCLUSIVE -> "Inconclusive"
            SrcuTimingVerdict.NOT_EVALUATED -> "Not evaluated"
        }
        SrcuTimingCollection.TIMED_OUT -> "Timed out; cleanup unconfirmed"
        SrcuTimingCollection.BUSY -> "Experiment already running"
        SrcuTimingCollection.PERMISSION_TREE_UNAVAILABLE -> "Permission tree unavailable"
        SrcuTimingCollection.CLEANUP_FAILED -> "Cleanup failed"
        SrcuTimingCollection.TRIGGER_FAILED -> "Trigger failed"
        SrcuTimingCollection.NATIVE_FAILED -> "Native collection failed"
        SrcuTimingCollection.IPC_FAILED -> "Carrier unavailable"
    }
    val detail = buildString {
        appendLine("Compares whole-instance inotify close latency during a synchronous packages.list stimulus, matched idle windows, and post-stimulus sequential controls.")
        appendLine("Experimental supporting evidence of global fsnotify/SRCU contention; it does not identify KernelSU. KernelSU ab23091e moved normal scans outside this reader; 6b5f55bd also removed the manager-absent full scan. No delay cannot exclude KernelSU.")
        appendLine("Android 11–14 legacy permission backend only; Android 15+ persists dynamic permissions separately. Kernel branch matching is a conservative gate, not proof that a vendor kept ACK semantics.")
        appendLine("Criterion: 12 complete rounds, at least 8 candidate-overlap samples per arm, 10 delayed rounds with replication in each four-round block, and a p95 gap over 6 control scales (maximum of MAD and one tenth of the control median). Thresholds await device calibration; concurrent scans and background readers remain confounders.")
        appendLine("kernel=${observation.kernelRelease}; collection=${observation.collection}; cleanup=${observation.cleanupCompleted}")
        appendLine("rounds=${observation.rounds.size}; usable=${analysis.usableRounds}; delayed=${analysis.delayedRounds}")
        appendLine("p95 ns: idle=${analysis.idleP95Nanos}, stimulated=${analysis.stimulatedP95Nanos}, sequential=${analysis.sequentialP95Nanos}")
        if (observation.failureDetail.isNotEmpty()) appendLine(observation.failureDetail)
        observation.failedWindow?.let { window ->
            appendLine("failed window=${window.beginNanos}..${window.endNanos} saturated=${window.saturated}")
            window.samples.forEach { sample -> appendLine("stage=${sample.stage} errno=${sample.errorNumber}") }
        }
        observation.rounds.forEachIndexed { index, round ->
            listOf(round.idle, round.stimulated, round.sequential).forEachIndexed { arm, window ->
                appendLine("round=$index arm=$arm window=${window.beginNanos}..${window.endNanos} saturated=${window.saturated}")
                window.samples.forEach { sample ->
                    appendLine("close=${sample.beginNanos}..${sample.endNanos} ns=${sample.durationNanos} stage=${sample.stage} errno=${sample.errorNumber}")
                }
            }
        }
    }.trimEnd()
    return NativeRootDetailRowModel(
        label = "fsnotifySrcuCloseTiming", value = value,
        status = if (analysis.verdict == SrcuTimingVerdict.REPEATABLE_DELAY) DetectorStatus.warning()
            else DetectorStatus.info(InfoKind.SUPPORT),
        detail = detail, hiddenCopyText = detail, detailMonospace = true,
    )
}
