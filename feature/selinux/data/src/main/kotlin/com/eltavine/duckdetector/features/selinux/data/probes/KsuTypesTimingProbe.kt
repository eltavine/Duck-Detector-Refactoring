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

package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.hasTimingDirectionImbalance

internal object KsuTypesTimingProbe {

    private const val BATCH_COUNT = 9
    private const val LEGACY_PAIRS_PER_BATCH = 512L
    private const val COUNT_OFFSET = BATCH_COUNT + 1
    private const val PAIR_COUNT_INDEX = COUNT_OFFSET + 2 * BATCH_COUNT
    private const val LEGACY_MEDIAN_INDEX = 2 * BATCH_COUNT
    private const val LEGACY_COUNT_OFFSET = LEGACY_MEDIAN_INDEX + 2
    private const val LEGACY_PAIR_COUNT_INDEX = LEGACY_COUNT_OFFSET + 4 * BATCH_COUNT

    private data class DirectionCounts(val slower: Long, val faster: Long, val equal: Long) {
        val exceedsThreshold: Boolean get() = hasTimingDirectionImbalance(slower, faster, equal)
    }

    fun interpret(differencesNs: List<Long>?, oracle: SelinuxOracle = SelinuxOracle.KSU_CONTEXT_TIMING): SelinuxCheckResult {
        val currentPayload = differencesNs?.size == PAIR_COUNT_INDEX + 1
        val pairCountIndex = if (currentPayload) PAIR_COUNT_INDEX else LEGACY_PAIR_COUNT_INDEX
        val pairsPerBatch = differencesNs?.getOrNull(pairCountIndex) ?: LEGACY_PAIRS_PER_BATCH
        if (differencesNs == null || pairsPerBatch !in 1L..Int.MAX_VALUE.toLong() ||
            (!currentPayload && differencesNs.size !in setOf(
                LEGACY_MEDIAN_INDEX, LEGACY_COUNT_OFFSET, LEGACY_PAIR_COUNT_INDEX, LEGACY_PAIR_COUNT_INDEX + 1,
            ))
        ) {
            return SelinuxCheckResult(
                method = oracle.label,
                oracle = oracle,
                status = "Unavailable",
                isSecure = null,
                permissionDenied = false,
                details = if (oracle == SelinuxOracle.KSU_PROC_ATTR_TIMING) {
                    "No complete ARM64 timing sample from rejected attr/current writes in the app zygote child."
                } else {
                    "SELinux context timing with the ARM64 hardware counter was unavailable in app zygote."
                },
            )
        }

        val batches = differencesNs.subList(0, BATCH_COUNT)
        val trimmedNs = trimmedPairMeanNs(batches, pairsPerBatch)
        val countOffset = if (currentPayload) COUNT_OFFSET else LEGACY_COUNT_OFFSET
        val counts = readBatchCounts(differencesNs, countOffset, pairsPerBatch)
        val total = counts?.let(::sumCounts)
        val medianIndex = if (currentPayload) BATCH_COUNT else LEGACY_MEDIAN_INDEX
        return SelinuxCheckResult(
            method = oracle.label,
            oracle = oracle,
            status = if (total != null) {
                val totalPairs = BATCH_COUNT * pairsPerBatch
                if (total.faster > total.slower) {
                    "A<B: ksu ${total.faster}/$totalPairs"
                } else {
                    "A>B: ksu ${total.slower}/$totalPairs"
                }
            } else {
                "Direction counts unavailable"
            },
            isSecure = total?.exceedsThreshold?.not(),
            permissionDenied = false,
            details = buildString {
                append("ARM64 A/B write timing (KSU minus invalid). ")
                differencesNs.getOrNull(medianIndex)?.let {
                    append("ksu per pair: median $it ns, mean ${meanPerPairNs(batches, pairsPerBatch)} ns. ")
                }
                append("Trimmed per-pair mean: ksu $trimmedNs ns.")
                if (counts != null && total != null) {
                    appendLine()
                    appendLine("Danger if either direction exceeds 3 × (opposite direction + ties), summed across $BATCH_COUNT batches.")
                    append("ksu totals: A>B ${total.slower}, A<B ${total.faster}, A=B ${total.equal}")
                    appendLine()
                    appendBatchCounts(batches, counts, pairsPerBatch)
                }
            },
        )
    }

    private fun readBatchCounts(samples: List<Long>, offset: Int, pairsPerBatch: Long): List<DirectionCounts>? {
        if (samples.size < offset + 2 * BATCH_COUNT) return null
        return List(BATCH_COUNT) { batch ->
            val slower = samples[offset + 2 * batch]
            val faster = samples[offset + 2 * batch + 1]
            if (slower !in 0L..pairsPerBatch || faster !in 0L..(pairsPerBatch - slower)) return null
            DirectionCounts(slower, faster, pairsPerBatch - slower - faster)
        }
    }

    private fun sumCounts(batches: List<DirectionCounts>): DirectionCounts =
        DirectionCounts(batches.sumOf { it.slower }, batches.sumOf { it.faster }, batches.sumOf { it.equal })

    private fun trimmedPairMeanNs(batchDifferencesNs: List<Long>, pairsPerBatch: Long): Long {
        // Equal-size batches sort the same by total or mean. Divide only after trimming to retain precision.
        val trimmed = batchDifferencesNs.sorted().subList(1, batchDifferencesNs.lastIndex)
        return meanPerPairNs(trimmed, pairsPerBatch)
    }

    private fun meanPerPairNs(batches: List<Long>, pairsPerBatch: Long): Long =
        (batches.average() / pairsPerBatch).toLong()

    private fun StringBuilder.appendBatchCounts(
        batches: List<Long>,
        counts: List<DirectionCounts>,
        pairsPerBatch: Long,
    ) {
        appendLine()
        appendLine("ksu differences by batch:")
        repeat(BATCH_COUNT) { batch ->
            val (slower, faster, equal) = counts[batch]
            val different = slower + faster
            val meanNs = batches[batch] / pairsPerBatch
            appendLine(
                "Batch ${batch + 1}: $different/$pairsPerBatch differ " +
                    "(A>B $slower, A<B $faster, A=B $equal), mean $meanNs ns",
            )
        }
    }
}
