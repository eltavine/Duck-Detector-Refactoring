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
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingObservation
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingVerdict
import com.eltavine.duckdetector.features.nativeroot.presentation.model.NativeRootDetailRowModel

internal fun kernelSuTimingRow(observation: KernelSuTimingObservation): NativeRootDetailRowModel {
    val verdict = observation.verdict
    val value = when (verdict) {
        KernelSuTimingVerdict.REPEATED_PATTERN -> "Repeated timing pattern (supporting)"
        KernelSuTimingVerdict.NOT_OBSERVED -> "Pattern not observed"
        KernelSuTimingVerdict.NOT_EVALUATED -> if (observation.collection == KernelSuTimingCollection.UNSUPPORTED)
            "Unsupported ABI or UID" else "Not run"
        KernelSuTimingVerdict.INCONCLUSIVE -> when (observation.collection) {
            KernelSuTimingCollection.NONINTERACTIVE -> "Incomplete: noninteractive"
            KernelSuTimingCollection.CANCELLED -> "Cancelled"
            KernelSuTimingCollection.TIMED_OUT -> "Deadline exceeded"
            KernelSuTimingCollection.WORKER_DIED -> "Worker died; cause unknown"
            KernelSuTimingCollection.PREFLIGHT_REJECTED -> "Preflight rejected"
            KernelSuTimingCollection.PROTOCOL_ERROR -> "Invalid worker reply"
            else -> "Incomplete or unavailable"
        }
    }
    val detail = buildString {
        appendLine("Supporting AArch64 prctl timing observation; not a KernelSU or root identification. Absence does not exclude either.")
        appendLine("collection=${observation.collection}; verdict=$verdict; cleanup=${observation.cleanupCompleted}")
        appendLine("counterFrequencyHz=${observation.counterFrequencyHz}; unit=CNTVCT ticks (not CPU cycles or nanoseconds)")
        appendLine("preflight=${observation.preflight.status}; bins=${observation.preflight.binCount}; minimumTicks=${observation.preflight.minimumTicks}")
        appendLine("enumeratedCpus=${observation.enumeratedCpus}; attemptedCpus=${observation.attempts.map { it.requestedCpu }}")
        if (observation.detail.isNotEmpty()) appendLine(observation.detail)
        observation.attempts.forEach { core ->
            appendLine("cpu=${core.requestedCpu}; actual=${core.actualCpu}; status=${core.status}; confirmed=${core.confirmed}")
            core.rounds.forEachIndexed { index, round ->
                appendLine("round=$index; distance=${round.distance}; similarity=${round.similarity}; matched=${round.matched}")
            }
        }
    }.trimEnd()
    return NativeRootDetailRowModel("kernelSuPrctlTiming", value,
        if (verdict == KernelSuTimingVerdict.REPEATED_PATTERN) DetectorStatus.warning()
        else DetectorStatus.info(InfoKind.SUPPORT), detail = detail, hiddenCopyText = detail, detailMonospace = true)
}
