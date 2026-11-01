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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxAvcLookupSnapshot.Companion.PAIRS
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxAvcLookupSnapshot.Companion.ROUNDS
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxAvcLookupSnapshot.Companion.WRITES_PER_BATCH
import com.eltavine.duckdetector.core.native.NativePayloadCodec

/**
 * The payload the native bridge writes and the preload snapshot retains. A rejected payload decodes
 * to an unavailable snapshot rather than throwing, so it cannot discard the rest of the carrier record.
 */
internal object SelinuxAvcLookupPayloadCodec {
    private const val UINT32_MAX = 4_294_967_295L
    private const val MAX_ERRNO = 4095L
    private val COUNTING_STEPS = setOf(
        SelinuxAvcLookupStep.AFFINITY, SelinuxAvcLookupStep.CPU_MAP,
        SelinuxAvcLookupStep.STATS, SelinuxAvcLookupStep.COUNTING,
    )

    fun decode(raw: String): SelinuxAvcLookupSnapshot {
        val values = linkedMapOf<String, String>()
        raw.lineSequence().filter { it.isNotBlank() }.forEach { line ->
            if ('=' !in line) return malformed("a line has no key")
            val key = line.substringBefore('=')
            if (values.put(key, NativePayloadCodec.decodeValue(line.substringAfter('='))) != null) {
                return malformed("$key repeats")
            }
        }
        if (values["SCHEMA"] != "1") return malformed("the schema is not 1")
        val state = SelinuxAvcLookupState.entries.firstOrNull { it.name == values["STATE"] }
            ?: return malformed("the state is unknown")
        var invalid: String? = null
        fun number(key: String, default: Long, range: LongRange): Long {
            val value = values[key] ?: return default
            return value.toLongOrNull()?.takeIf { it in range } ?: default.also { invalid = invalid ?: key }
        }
        fun <T : Enum<T>> named(key: String, entries: List<T>): T? {
            val value = values[key] ?: return null
            return entries.firstOrNull { it.name == value } ?: null.also { invalid = invalid ?: key }
        }
        fun batches(key: String): List<Long> {
            val value = values[key] ?: return emptyList()
            val counts = value.split(',').map { it.toLongOrNull()?.takeIf { count -> count in 0..UINT32_MAX } }
            return if (counts.size == ROUNDS && counts.all { it != null }) counts.filterNotNull()
            else emptyList<Long>().also { invalid = invalid ?: key }
        }
        val snapshot = SelinuxAvcLookupSnapshot(
            state = state,
            step = named("STEP", SelinuxAvcLookupStep.entries),
            errno = number("ERRNO", 0, 0..MAX_ERRNO).toInt(),
            unexpectedPayload = named("UNEXPECTED_PAYLOAD", SelinuxAvcLookupPayload.entries) ?: SelinuxAvcLookupPayload.NONE,
            unexpectedReturned = number("UNEXPECTED_RETURNED", 0, -1L..WRITES_PER_BATCH),
            identityChanged = number("IDENTITY_CHANGED", 0, 0L..1L) == 1L,
            cpu = number("CPU", -1, -1L..1023L).toInt(),
            cpuRow = number("CPU_ROW", -1, -1L..255L).toInt(),
            cpuRows = number("CPU_ROWS", 0, 0L..256L).toInt(),
            possibleCpus = number("POSSIBLE_CPUS", 0, 0L..256L).toInt(),
            pairs = number("PAIRS", 0, 0L..PAIRS).toInt(),
            pid = number("PID", -1, -1L..Int.MAX_VALUE.toLong()).toInt(),
            cpuMigrations = number("CPU_MIGRATIONS", 0, 0L..PAIRS).toInt(),
            timingMediansAvailable = number("TIMING_MEDIANS_VALID",
                if (state == SelinuxAvcLookupState.COLLECTED || state == SelinuxAvcLookupState.TIMING_ONLY) 1 else 0,
                0L..1L) == 1L,
            aSlower = number("A_SLOWER", 0, 0L..PAIRS).toInt(),
            positiveBlocks = number("POSITIVE_BLOCKS", 0, 0L..(PAIRS / 32)).toInt(),
            negativeBlocks = number("NEGATIVE_BLOCKS", 0, 0L..(PAIRS / 32)).toInt(),
            zeroBlocks = number("ZERO_BLOCKS", 0, 0L..(PAIRS / 32)).toInt(),
            rounds = number("ROUNDS", 0, 0L..ROUNDS).toInt(),
            writesPerBatch = number("WRITES", 0, 0L..WRITES_PER_BATCH).toInt(),
            batchesA = batches("BATCH_A"),
            batchesB = batches("BATCH_B"),
            medianANs = number("MEDIAN_A_NS", 0, 0L..Long.MAX_VALUE),
            medianBNs = number("MEDIAN_B_NS", 0, 0L..Long.MAX_VALUE),
            medianDeltaNs = number("MEDIAN_DELTA_NS", 0, Long.MIN_VALUE..Long.MAX_VALUE),
            childEnd = named("CHILD_END", SelinuxAvcLookupChildEnd.entries),
            childExitStatus = number("CHILD_EXIT", 0, 0L..255L).toInt(),
            childSignal = number("CHILD_SIGNAL", 0, 0L..127L).toInt(),
            childErrno = number("CHILD_ERRNO", 0, 0..MAX_ERRNO).toInt(),
            failureReason = values["FAILURE_REASON"],
            parentTiming = decodeParentValues(values),
        )
        invalid?.let { return malformed("$it is malformed or out of range") }
        if (!snapshot.consistent()) return malformed("the ${state.name} record is incomplete")
        return snapshot
    }

    fun encode(snapshot: SelinuxAvcLookupSnapshot): String = buildString {
        fun entry(key: String, value: Any?) {
            if (value != null) append(key).append('=').append(NativePayloadCodec.encodeValue(value.toString())).append('\n')
        }
        entry("SCHEMA", 1)
        entry("STATE", snapshot.state.name)
        entry("STEP", snapshot.step?.name)
        entry("ERRNO", snapshot.errno)
        entry("UNEXPECTED_PAYLOAD", snapshot.unexpectedPayload.name)
        entry("UNEXPECTED_RETURNED", snapshot.unexpectedReturned)
        entry("IDENTITY_CHANGED", if (snapshot.identityChanged) 1 else 0)
        entry("CPU", snapshot.cpu)
        entry("CPU_ROW", snapshot.cpuRow)
        entry("CPU_ROWS", snapshot.cpuRows)
        entry("POSSIBLE_CPUS", snapshot.possibleCpus)
        entry("PAIRS", snapshot.pairs)
        entry("PID", snapshot.pid)
        entry("CPU_MIGRATIONS", snapshot.cpuMigrations)
        entry("TIMING_MEDIANS_VALID", if (snapshot.timingMediansAvailable) 1 else 0)
        entry("A_SLOWER", snapshot.aSlower)
        entry("POSITIVE_BLOCKS", snapshot.positiveBlocks)
        entry("NEGATIVE_BLOCKS", snapshot.negativeBlocks)
        entry("ZERO_BLOCKS", snapshot.zeroBlocks)
        entry("ROUNDS", snapshot.rounds)
        entry("WRITES", snapshot.writesPerBatch)
        entry("BATCH_A", snapshot.batchesA.takeIf { it.isNotEmpty() }?.joinToString(","))
        entry("BATCH_B", snapshot.batchesB.takeIf { it.isNotEmpty() }?.joinToString(","))
        entry("MEDIAN_A_NS", snapshot.medianANs)
        entry("MEDIAN_B_NS", snapshot.medianBNs)
        entry("MEDIAN_DELTA_NS", snapshot.medianDeltaNs)
        entry("CHILD_END", snapshot.childEnd?.name)
        entry("CHILD_EXIT", snapshot.childExitStatus)
        entry("CHILD_SIGNAL", snapshot.childSignal)
        entry("CHILD_ERRNO", snapshot.childErrno)
        entry("FAILURE_REASON", snapshot.failureReason)
        snapshot.parentTiming.takeIf { it.attempted }?.let { parent ->
            entry("PARENT_ATTEMPTED", 1)
            entry("PARENT_PROTOCOL", parent.protocol)
            entry("PARENT_POSITIVE_BLOCKS", parent.positiveBlocks)
            entry("PARENT_NEGATIVE_BLOCKS", parent.negativeBlocks)
            entry("PARENT_ZERO_BLOCKS", parent.zeroBlocks)
            entry("PARENT_COMPLETE", if (parent.complete) 1 else 0)
            entry("PARENT_ERROR", parent.error)
            entry("PARENT_PID", parent.pid)
            entry("PARENT_CPU", parent.cpu)
            entry("PARENT_PAIRS", parent.pairs)
            entry("PARENT_MIGRATIONS", parent.migrations)
            entry("PARENT_A_SLOWER", parent.aSlower)
            entry("PARENT_MEDIANS_VALID", if (parent.medianDeltaNs != null) 1 else 0)
            entry("PARENT_MEDIAN_A_NS", parent.medianANs)
            entry("PARENT_MEDIAN_B_NS", parent.medianBNs)
            entry("PARENT_MEDIAN_DELTA_NS", parent.medianDeltaNs)
        }
    }

    fun decodeParent(raw: String): SelinuxAvcParentTiming {
        val fields = linkedMapOf<String, String>()
        for (line in raw.lineSequence().filter { it.isNotBlank() }) {
            val key = line.substringBefore('=', missingDelimiterValue = "")
            if (!key.startsWith("PARENT_") || fields.put(key, line.substringAfter('=')) != null)
                return SelinuxAvcParentTiming()
        }
        return decodeParentValues(fields)
    }

    private fun decodeParentValues(fields: Map<String, String>): SelinuxAvcParentTiming {
        if (fields["PARENT_ATTEMPTED"] != "1") return SelinuxAvcParentTiming()
        fun int(key: String, min: Int, max: Int): Int? =
            fields[key]?.toIntOrNull()?.takeIf { it in min..max }
        val error = int("PARENT_ERROR", 0, MAX_ERRNO.toInt()) ?: return SelinuxAvcParentTiming()
        val pid = int("PARENT_PID", -1, Int.MAX_VALUE) ?: return SelinuxAvcParentTiming()
        val cpu = int("PARENT_CPU", -1, 1023) ?: return SelinuxAvcParentTiming()
        val pairs = int("PARENT_PAIRS", 0, PAIRS) ?: return SelinuxAvcParentTiming()
        val migrations = int("PARENT_MIGRATIONS", 0, PAIRS) ?: return SelinuxAvcParentTiming()
        val slower = int("PARENT_A_SLOWER", 0, pairs) ?: return SelinuxAvcParentTiming()
        val protocol = if ("PARENT_PROTOCOL" in fields)
            int("PARENT_PROTOCOL", 0, 1) ?: return SelinuxAvcParentTiming() else 0
        val positive = if (protocol == 1) int("PARENT_POSITIVE_BLOCKS", 0, 16)
            ?: return SelinuxAvcParentTiming() else 0
        val negative = if (protocol == 1) int("PARENT_NEGATIVE_BLOCKS", 0, 16)
            ?: return SelinuxAvcParentTiming() else 0
        val zero = if (protocol == 1) int("PARENT_ZERO_BLOCKS", 0, 16)
            ?: return SelinuxAvcParentTiming() else 0
        if (fields["PARENT_COMPLETE"] !in setOf("0", "1") ||
            fields["PARENT_MEDIANS_VALID"] !in setOf("0", "1")) return SelinuxAvcParentTiming()
        val complete = fields["PARENT_COMPLETE"] == "1"
        val haveMedians = fields["PARENT_MEDIANS_VALID"] == "1"
        fun median(key: String, nonnegative: Boolean): Long? = fields[key]?.toLongOrNull()
            ?.takeIf { !nonnegative || it >= 0 }
        val a = if (haveMedians) median("PARENT_MEDIAN_A_NS", true) else null
        val b = if (haveMedians) median("PARENT_MEDIAN_B_NS", true) else null
        val delta = if (haveMedians) median("PARENT_MEDIAN_DELTA_NS", false) else null
        if (haveMedians && (a == null || b == null || delta == null)) return SelinuxAvcParentTiming()
        if (protocol == 1 && (positive + negative + zero != pairs / 32 ||
                (complete && (pid <= 0 || cpu < 0)))) return SelinuxAvcParentTiming()
        if (complete && (error != 0 || pairs != PAIRS || migrations != 0 || !haveMedians))
            return SelinuxAvcParentTiming()
        return SelinuxAvcParentTiming(true, complete, error, pid, cpu, pairs, migrations, slower, a, b, delta,
            protocol, positive, negative, zero)
    }

    // Only collected counts and completed timing are interpreted, so only those records must be whole.
    private fun SelinuxAvcLookupSnapshot.consistent(): Boolean {
        // Legacy 128-pair preload payloads stay readable but are never timing-positive.
        val cleanChild = childEnd == SelinuxAvcLookupChildEnd.EXITED && childExitStatus == 0 && childSignal == 0 &&
            unexpectedPayload == SelinuxAvcLookupPayload.NONE && !identityChanged && pairs in setOf(128, PAIRS) &&
            aSlower <= pairs && positiveBlocks + negativeBlocks + zeroBlocks <= pairs / 32
        return when (state) {
            SelinuxAvcLookupState.COLLECTED -> cleanChild && step == SelinuxAvcLookupStep.FINISHED && errno == 0 &&
                rounds == ROUNDS && writesPerBatch == WRITES_PER_BATCH &&
                batchesA.size == ROUNDS && batchesB.size == ROUNDS &&
                cpu >= 0 && cpuRow in 0 until cpuRows && cpuRows == possibleCpus
            SelinuxAvcLookupState.TIMING_ONLY -> cleanChild && step in COUNTING_STEPS && errno > 0
            else -> true
        }
    }

    private fun malformed(reason: String) = SelinuxAvcLookupSnapshot(
        state = SelinuxAvcLookupState.UNAVAILABLE,
        failureReason = "AVC lookup payload was rejected: $reason.",
    )
}
