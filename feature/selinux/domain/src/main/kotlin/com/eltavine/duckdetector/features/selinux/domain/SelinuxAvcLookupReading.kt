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

package com.eltavine.duckdetector.features.selinux.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind

/** AVC lookups per rejected write of payload A and payload B; [label] is the status it is shown with. */
enum class SelinuxAvcLookupProfile(val label: String) {
    ONE_ONE("A≈1 / B≈1 lookups per write"),
    ONE_TWO("A≈1 / B≈2 lookups per write"),
    TWO_TWO("A≈2 / B≈2 lookups per write"),
    UNCLASSIFIED("Counts outside the 1× and 2× bands"),
}

enum class SelinuxAvcLookupCollection(val label: String) {
    NOT_COLLECTED("Not collected"),
    COLLECTED("Collected"),
    TIMING_ONLY("Timing only, counters unavailable"),
    PERMISSION_LIMITED("Permission limited"),
    UNSUPPORTED("Unsupported"),
    UNAVAILABLE("Unavailable"),
    INCONCLUSIVE("Inconclusive"),
}

data class SelinuxAvcLookupCollectionDetails(
    val step: String?,
    val errno: Int,
    /** The payload whose write did not fail with EINVAL and what it returned, when one did not. */
    val unexpectedWrite: String?,
    val identityChanged: Boolean,
    val childEnd: String?,
    val childExitStatus: Int,
    val childSignal: Int,
    val childErrno: Int,
    val cpu: Int,
    val cpuRow: Int,
    val cpuRows: Int,
    val possibleCpus: Int,
    val failureReason: String?,
)

data class SelinuxAvcLookupReading(
    val collection: SelinuxAvcLookupCollection,
    val writesPerBatch: Int,
    val batchesA: List<Long>,
    val batchesB: List<Long>,
    val completedRounds: Int,
    val pairs: Int,
    val medianANs: Long,
    val medianBNs: Long,
    val medianDeltaNs: Long,
    val details: SelinuxAvcLookupCollectionDetails,
) {
    /** Only collected counts are classified; timing is shown but never classified. */
    val profile: SelinuxAvcLookupProfile?
        get() {
            if (collection != SelinuxAvcLookupCollection.COLLECTED) return null
            if (writesPerBatch <= 0 || batchesA.isEmpty() || batchesA.size != batchesB.size)
                return SelinuxAvcLookupProfile.UNCLASSIFIED
            val a = batchesA.map(::lookupsPerWrite).distinct().singleOrNull()
            val b = batchesB.map(::lookupsPerWrite).distinct().singleOrNull()
            return when {
                a == 1 && b == 1 -> SelinuxAvcLookupProfile.ONE_ONE
                a == 1 && b == 2 -> SelinuxAvcLookupProfile.ONE_TWO
                a == 2 && b == 2 -> SelinuxAvcLookupProfile.TWO_TWO
                else -> SelinuxAvcLookupProfile.UNCLASSIFIED
            }
        }

    /** The stock handler costs one lookup per write for both payloads; these profiles cost more. */
    val extraLookupObserved: Boolean
        get() = profile == SelinuxAvcLookupProfile.ONE_TWO || profile == SelinuxAvcLookupProfile.TWO_TWO

    val label: String get() = profile?.label ?: collection.label

    // A shared per-CPU counter cannot attribute a lookup to any code, so no reading raises the card.
    val status: DetectorStatus get() = DetectorStatus.info(InfoKind.SUPPORT)

    val rateA: Double? get() = rate(batchesA)
    val rateB: Double? get() = rate(batchesB)

    // Every rejected write adds its handler's lookups to the pinned CPU's counter, and other tasks on
    // that CPU and the counter reads can only add more. An n-lookup path therefore leaves a batch in
    // [n, n + 0.1] × writes unless that extra activity exceeded a tenth of the batch.
    private fun lookupsPerWrite(batch: Long): Int? = when (batch) {
        in writesPerBatch.toLong()..writesPerBatch * 11L / 10 -> 1
        in 2L * writesPerBatch..writesPerBatch * 21L / 10 -> 2
        else -> null
    }

    private fun rate(batches: List<Long>): Double? =
        if (collection == SelinuxAvcLookupCollection.COLLECTED && writesPerBatch > 0 && batches.isNotEmpty())
            batches.sum().toDouble() / (batches.size.toLong() * writesPerBatch) else null
}

fun avcLookupReading(report: SelinuxReport): SelinuxAvcLookupReading? =
    report.methods.firstOrNull { it.oracle == SelinuxOracle.APP_ZYGOTE_AVC_LOOKUPS }?.avcLookup
