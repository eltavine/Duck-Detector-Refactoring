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

enum class SelinuxSidtabVerdict(val label: String) {
    NOT_OBSERVED("No discrepancy observed"),
    DISCREPANCY_OBSERVED("Repeated SID-table discrepancy"),
    NOT_COLLECTED("Not collected"),
    UNSUPPORTED("Unsupported"),
    PERMISSION_LIMITED("Permission limited"),
    UNAVAILABLE("Unavailable"),
    INCONCLUSIVE("Inconclusive"),
}

enum class SelinuxSidtabCollection { NOT_COLLECTED, COMPLETE, UNSUPPORTED, PERMISSION_LIMITED, UNAVAILABLE, INCONCLUSIVE }

data class SelinuxSidtabTransaction(
    val context: String,
    val contextErrno: Int?,
    val attrErrno: Int?,
    val repeatErrno: Int?,
)

data class SelinuxSidtabCollectionDetails(
    val phase: String,
    val errno: Int?,
    val childEnd: String?,
    val signal: Int?,
    val carrier: String?,
    val uid: Int?,
    val pid: Int?,
    val kernelRelease: String?,
    val failureReason: String?,
)

data class SelinuxSidtabRound(
    val beforeControls: Long?,
    val before: Long?,
    val afterContext: Long?,
    val afterAttr: Long?,
    val afterRepeat: Long?,
    val idleEnd: Long?,
    val controlsPassed: Boolean,
    val contexts: List<String>,
    val contextWritesAccepted: Boolean,
    val attrWritesRejected: Boolean,
    val repeatWritesAccepted: Boolean,
    val transactions: List<SelinuxSidtabTransaction> = emptyList(),
    val positiveErrno: Int? = null,
    val negativeErrno: Int? = null,
    val stockContextsVerified: Boolean = false,
    val attrNegativeErrno: Int? = null,
)

data class SelinuxSidtabReading(
    val collection: SelinuxSidtabCollection,
    val attempted: Boolean,
    val completedRounds: Int,
    val carrierVerified: Boolean,
    val canonicalMismatch: Boolean,
    val identityChanged: Boolean,
    val capturedUptimeMs: Long?,
    val rounds: List<SelinuxSidtabRound>,
    val collectionDetails: SelinuxSidtabCollectionDetails,
) {
    val verdict: SelinuxSidtabVerdict
        get() {
            when (collection) {
                SelinuxSidtabCollection.NOT_COLLECTED -> return SelinuxSidtabVerdict.NOT_COLLECTED
                SelinuxSidtabCollection.UNSUPPORTED -> return SelinuxSidtabVerdict.UNSUPPORTED
                SelinuxSidtabCollection.PERMISSION_LIMITED -> return SelinuxSidtabVerdict.PERMISSION_LIMITED
                SelinuxSidtabCollection.UNAVAILABLE -> return SelinuxSidtabVerdict.UNAVAILABLE
                SelinuxSidtabCollection.INCONCLUSIVE -> return SelinuxSidtabVerdict.INCONCLUSIVE
                SelinuxSidtabCollection.COMPLETE -> Unit
            }
            if (!attempted || !carrierVerified || canonicalMismatch || identityChanged ||
                completedRounds != 2 || rounds.size != 2 || rounds.any { !it.usable() }
            ) return SelinuxSidtabVerdict.INCONCLUSIVE
            val contexts = rounds.flatMap { it.contexts }
            if (contexts.distinct().size != 8 || rounds[0].idleEnd != rounds[1].beforeControls)
                return SelinuxSidtabVerdict.INCONCLUSIVE
            // Aggregate statistics cannot attribute each insertion to us or exclude a hidden reload.
            // Only a repeated paired pattern is a warning, never root/tool identity or a strong finding.
            if (rounds.all { it.afterContext == it.before && it.afterAttr!! - it.afterContext!! == 4L })
                return SelinuxSidtabVerdict.DISCREPANCY_OBSERVED
            if (rounds.all { it.afterContext!! - it.before!! == 4L && it.afterAttr == it.afterContext })
                return SelinuxSidtabVerdict.NOT_OBSERVED
            return SelinuxSidtabVerdict.INCONCLUSIVE
        }

    val status: DetectorStatus
        get() = if (verdict == SelinuxSidtabVerdict.DISCREPANCY_OBSERVED) DetectorStatus.warning()
        else DetectorStatus.info(InfoKind.SUPPORT)

    private fun SelinuxSidtabRound.usable(): Boolean {
        val counts = listOf(beforeControls, before, afterContext, afterAttr, afterRepeat, idleEnd)
        return counts.all { it != null && it >= 0 && it <= Int.MAX_VALUE } &&
            controlsPassed && contexts.size == 4 && stockContextsVerified &&
            contextWritesAccepted && attrWritesRejected && repeatWritesAccepted &&
            beforeControls == before && afterAttr == afterRepeat && afterRepeat == idleEnd &&
            afterContext!! >= before!! && afterAttr!! >= afterContext
    }
}

fun sidtabReading(report: SelinuxReport): SelinuxSidtabReading? =
    report.methods.firstOrNull { it.oracle == SelinuxOracle.SIDTAB_CONSISTENCY }?.sidtab
