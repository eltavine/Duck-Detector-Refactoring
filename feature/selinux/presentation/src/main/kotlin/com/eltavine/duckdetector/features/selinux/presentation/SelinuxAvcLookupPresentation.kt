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

package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.features.selinux.domain.SelinuxAvcLookupCollection
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAvcLookupProfile
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAvcLookupReading
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAppZygoteTimingVerdict
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.presentation.model.SelinuxDetailRowModel
import java.util.Locale

internal const val AVC_EXTRA_LOOKUP_IMPACT =
    "Rejected app_zygote attr/current writes repeatedly cost an extra AVC lookup. The per-CPU counter is shared " +
        "and does not show which code queried it; this is supporting evidence, not tool identification or root proof."

internal fun appZygoteTimingRow(result: SelinuxCheckResult): SelinuxDetailRowModel {
    val reading = requireNotNull(result.avcLookup)
    val verdict = reading.timingVerdict
    val medians = reading.timingMediansAvailable
    val parent = reading.parentTiming
    fun measured(value: Long): String = if (medians) "$value ns" else "N/A"
    val missingEvidence = reading.details.failureReason?.takeIf {
        reading.collection != SelinuxAvcLookupCollection.COLLECTED &&
            reading.collection != SelinuxAvcLookupCollection.TIMING_ONLY
    }
    return SelinuxDetailRowModel(
        label = result.method,
        value = verdict.label,
        status = when (verdict) {
            SelinuxAppZygoteTimingVerdict.POSITIVE -> com.eltavine.duckdetector.core.evidence.DetectorStatus.danger()
            else -> com.eltavine.duckdetector.core.evidence.DetectorStatus.info(
                com.eltavine.duckdetector.core.evidence.InfoKind.SUPPORT
            )
        },
        detail = (missingEvidence?.let { "Collection failed: $it No timing samples were obtained; this is not a negative detection.\n" }
            ?: if (reading.collection == SelinuxAvcLookupCollection.NOT_COLLECTED) {
                "No App Zygote timing sample was collected; this is not a negative detection.\n"
            } else "") +
            "A=invalid type, B=same-length newline prefix; both must return EINVAL. " +
            "512 AB/BA pairs, 32 warmups; CLOCK_MONOTONIC_RAW; paired A−B median > 0 ns is positive. " +
            "Measured in the preload parent with scheduler-selected CPUs, matching the standalone PoC. " +
            "Within-pair CPU migrations or incomplete samples invalidate classification. " +
            "One retained preload is one measurement.\n" +
            (if (parent.attempted) "Parent preload (PID=${parent.pid}, entry CPU=${parent.cpu}): " +
                "A−B=${parent.medianDeltaNs?.let { "$it ns" } ?: "N/A"}; " +
                "A=${parent.medianANs?.let { "$it ns" } ?: "N/A"}, " +
                "B=${parent.medianBNs?.let { "$it ns" } ?: "N/A"}; " +
                "A slower=${parent.aSlower}/${parent.pairs}; " +
                "blocks positive/negative/zero=${parent.positiveBlocks}/${parent.negativeBlocks}/${parent.zeroBlocks}; " +
                "migrations=${parent.migrations}; complete=${parent.complete}; errno=${parent.error}. " +
                (if (parent.protocol == 1) "This parent sample supplies the timing verdict. "
                 else "Legacy pinned parent diagnostic; unavailable for PoC classification. ") +
                (if (!parent.complete) "Partial-sample medians are diagnostic only. " else "")
            else "Parent preload: N/A (not collected). ") +
            "\nPinned child diagnostic (PID=${reading.details.childPid}, CPU=${reading.details.cpu}): " +
            "paired A−B=${measured(reading.medianDeltaNs)}; A=${measured(reading.medianANs)}, " +
            "B=${measured(reading.medianBNs)}; A slower=${reading.aSlower}/${reading.pairs}; " +
            "blocks positive/negative/zero=${reading.positiveBlocks}/${reading.negativeBlocks}/${reading.zeroBlocks}; " +
            "CPU migrations=${reading.cpuMigrations}; collection=${reading.collection.label}. " +
            "Child timing is diagnostic only and never replaces the parent sample. " +
            "Positive timing is a conditional SELinux Hide side-channel, not proof of a specific root tool.",
    )
}

internal fun avcLookupRow(result: SelinuxCheckResult): SelinuxDetailRowModel {
    val reading = requireNotNull(result.avcLookup)
    val details = reading.details
    return SelinuxDetailRowModel(
        label = result.method,
        value = reading.label,
        status = reading.status,
        detail = buildString {
            append(avcLookupExplanation(reading))
            if (reading.collection != SelinuxAvcLookupCollection.COLLECTED &&
                reading.collection != SelinuxAvcLookupCollection.TIMING_ONLY &&
                reading.details.failureReason != null
            ) append(" Collection failed: ${reading.details.failureReason}. This is not a negative detection.")
            append(" Captured during app_zygote preload; this is a retained measurement, not a live check.")
            append("\nStep=${details.step}; errno=${details.errno}; child=${details.childEnd}, ")
            append("exit=${details.childExitStatus}, signal=${details.childSignal}, errno=${details.childErrno}")
            details.unexpectedWrite?.let { append("; unexpected write: payload $it") }
            if (details.identityChanged) append("; carrier identity changed")
            append(".\nCPU ${details.cpu} is cache_stats row ${details.cpuRow} of ${details.cpuRows}; ")
            append("possible CPUs=${details.possibleCpus}. Rounds=${reading.completedRounds}; ")
            append("writes per batch=${reading.writesPerBatch}; A batches=${reading.batchesA.joinToString()}; ")
            append("B batches=${reading.batchesB.joinToString()}")
            reading.rateA?.let { append("; A rate=${String.format(Locale.ROOT, "%.3f", it)}") }
            reading.rateB?.let { append("; B rate=${String.format(Locale.ROOT, "%.3f", it)}") }
            append(".\nTiming over ${reading.pairs} pairs: median A=")
            append(if (reading.timingMediansAvailable) "${reading.medianANs} ns" else "N/A")
            append(", B=")
            append(if (reading.timingMediansAvailable) "${reading.medianBNs} ns" else "N/A")
            append(", paired A−B=")
            append(if (reading.timingMediansAvailable) "${reading.medianDeltaNs} ns" else "N/A")
            append(". ")
            append("The separate App Zygote timing row interprets a validated 512-pair sample; " +
                "the AVC profile still uses child counts only.")
            details.failureReason?.let { append("\n$it") }
        },
    )
}

internal fun avcLookupExplanation(reading: SelinuxAvcLookupReading): String = when (reading.profile) {
    SelinuxAvcLookupProfile.ONE_TWO ->
        "Payload B cost one more AVC lookup per rejected write than payload A in every round. A hook that checks " +
            "SETCURRENT before passing B to the stock handler produces this. The per-CPU counter is shared and does " +
            "not show which code queried it, so this is supporting evidence, not tool identification or root proof."
    SelinuxAvcLookupProfile.TWO_TWO ->
        "Both payloads cost two AVC lookups per rejected write in every round, one more than the stock handler. " +
            "The per-CPU counter is shared and does not show which code queried it, so this is supporting evidence, " +
            "not tool identification or root proof."
    SelinuxAvcLookupProfile.ONE_ONE ->
        "Both payloads cost one AVC lookup per rejected write, as the stock handler does. A hook that checks " +
            "SETCURRENT only after its own parse fails costs the same, so this is not a clean result."
    SelinuxAvcLookupProfile.UNCLASSIFIED ->
        "At least one batch fell outside the one- and two-lookup bands, as other activity on the pinned CPU can " +
            "cause. No lookup pattern is reported."
    null -> when (reading.collection) {
        SelinuxAvcLookupCollection.TIMING_ONLY ->
            "The paired writes were timed, but the per-CPU AVC counters were not collected. Kernels built without " +
                "CONFIG_SECURITY_SELINUX_AVC_STATS have no cache_stats node."
        SelinuxAvcLookupCollection.PERMISSION_LIMITED ->
            "The carrier could not open attr/current or was refused SETCURRENT, so the payloads never reached the " +
                "measured handler path."
        SelinuxAvcLookupCollection.UNSUPPORTED ->
            "The carrier identity or SELinux mode did not meet this experiment's requirements."
        SelinuxAvcLookupCollection.INCONCLUSIVE ->
            "A write result, identity change or child outcome did not fit the experiment, so no counts were interpreted."
        SelinuxAvcLookupCollection.UNAVAILABLE, SelinuxAvcLookupCollection.COLLECTED ->
            "The experiment could not produce a usable observation."
        SelinuxAvcLookupCollection.NOT_COLLECTED -> "No AVC lookup experiment was captured by this carrier."
    }
}
