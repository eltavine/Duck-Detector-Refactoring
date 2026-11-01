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
        KernelSuTimingVerdict.NOT_OBSERVED -> "Pattern not observed on all present CPUs"
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
        appendLine("coverageScope=all present CPUs; coverageStable=${observation.coverageStable}")
        appendLine("initialCpus=${observation.initialCpus}; finalCpus=${observation.finalCpus}")
        appendLine("sampledCpus=${observation.sampledCpus}; completedCpus=${observation.attempts.filter { it.completed }.map { it.requestedCpu }}")
        observation.initialCpus.present.orEmpty().forEachIndexed { index, cpu ->
            val reasons = buildList {
                if (observation.initialCpus.online == null) add("online state unavailable")
                else if (cpu !in observation.initialCpus.online.orEmpty()) add("offline")
                if (observation.initialCpus.allowed == null) add("affinity/cpuset unavailable")
                else if (cpu !in observation.initialCpus.allowed.orEmpty()) add("outside worker affinity/cpuset snapshot")
                if (index >= 16) add("CPU budget limit")
                if (observation.attempts.none { it.requestedCpu == cpu }) add("not sampled")
            }
            if (reasons.isNotEmpty()) appendLine("cpu=$cpu; exclusions=$reasons")
        }
        observation.finalCpus?.present.orEmpty().filter { it !in observation.initialCpus.present.orEmpty() }.forEach { cpu ->
            appendLine("cpu=$cpu; exclusions=[appeared after initial inventory, not sampled]")
        }
        if (observation.detail.isNotEmpty()) appendLine(observation.detail)
        observation.attempts.forEach { core ->
            appendLine("cpu=${core.requestedCpu}; actual=${core.actualCpu}; status=${core.status}; confirmed=${core.confirmed}")
            appendLine("preflight=${core.preflight.status}; bins=${core.preflight.binCount}; minimumTicks=${core.preflight.minimumTicks}")
            core.windows.forEachIndexed { index, window ->
                appendLine("window=$index; counterFrequencyHz=${window.counterFrequencyHz}; unit=CNTVCT ticks; stable=${window.stable}")
                appendLine("before=${window.before}; after=${window.after}; workerAllowed=${window.workerAllowed}")
                appendLine("syscallOutcomes=${window.outcomes}")
            }
            core.rounds.forEachIndexed { index, round ->
                appendLine("round=$index; distance=${round.distance}; similarity=${round.similarity}; validity=${round.validity}; support=${round.support}; matched=${round.matched}")
            }
        }
    }.trimEnd()
    return NativeRootDetailRowModel("kernelSuPrctlTiming", value,
        if (verdict == KernelSuTimingVerdict.REPEATED_PATTERN) DetectorStatus.warning()
        else DetectorStatus.info(InfoKind.SUPPORT), detail = detail, hiddenCopyText = detail, detailMonospace = true)
}
