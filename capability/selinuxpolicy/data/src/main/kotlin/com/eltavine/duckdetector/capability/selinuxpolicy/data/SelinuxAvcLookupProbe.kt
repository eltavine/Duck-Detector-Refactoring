// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.capability.selinuxpolicy.data

import com.eltavine.duckdetector.core.native.NativeSnapshotCollector

public enum class SelinuxAvcLookupState {
    NOT_COLLECTED, COLLECTED, TIMING_ONLY, PERMISSION_LIMITED, UNSUPPORTED, UNAVAILABLE, INCONCLUSIVE,
}

/** Informational per-CPU/global-statistics observation, NOT an avc_has_perm() call trace. */
public data class SelinuxAvcLookupSnapshot(
    val state: SelinuxAvcLookupState = SelinuxAvcLookupState.NOT_COLLECTED,
    val error: Int = 0,
    val statsError: Int = 0,
    val cpu: Int = -1,
    val cpuRows: Int = 0,
    val pairs: Int = 0,
    val rounds: Int = 0,
    val profile: Int = 0,
    val writesPerBatch: Int = 0,
    val lookupsA: Long = 0,
    val lookupsB: Long = 0,
    val batchesA: List<Long> = emptyList(),
    val batchesB: List<Long> = emptyList(),
    val medianANs: Long = 0,
    val medianBNs: Long = 0,
    val pairedDeltaNs: Long = 0,
    val childEnd: Int = -1,
) {
    public val rateA: Double? get() = if (state == SelinuxAvcLookupState.COLLECTED &&
        rounds > 0 && writesPerBatch > 0) lookupsA.toDouble() / (rounds * writesPerBatch) else null
    public val rateB: Double? get() = if (state == SelinuxAvcLookupState.COLLECTED &&
        rounds > 0 && writesPerBatch > 0) lookupsB.toDouble() / (rounds * writesPerBatch) else null
}

/** Native code runs only in a disposable child forked from the app_zygote preload. */
internal class SelinuxAvcLookupProbe(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
) {
    internal fun inspect(): SelinuxAvcLookupSnapshot = collector.collect(
        readPayload = ::nativeCollectAvcLookup,
        parse = SelinuxAvcLookupPayload::decode,
        unavailable = { SelinuxAvcLookupSnapshot(state = SelinuxAvcLookupState.UNAVAILABLE) },
    )

    private external fun nativeCollectAvcLookup(): String
}

internal object SelinuxAvcLookupPayload {
    fun decode(raw: String): SelinuxAvcLookupSnapshot {
        val fields = raw.lineSequence().filter { it.isNotBlank() }.associate { line ->
            require('=' in line) { "Malformed AVC lookup payload" }
            line.substringBefore('=') to line.substringAfter('=')
        }
        require(fields["SCHEMA"] == "1") { "Unknown AVC lookup schema" }
        val state = SelinuxAvcLookupState.entries.firstOrNull { it.name == fields["STATE"] }
            ?: error("Missing AVC lookup state")
        fun num(name: String) = fields[name]?.toLongOrNull() ?: error("Missing $name")
        fun batches(name: String): List<Long> = fields[name]?.split(',')?.map { it.toLongOrNull() ?: error("Invalid $name") }
            ?: error("Missing $name")
        val snapshot = SelinuxAvcLookupSnapshot(
            state = state,
            error = num("ERROR").toIntExact(),
            statsError = num("STATS_ERROR").toIntExact(),
            cpu = num("CPU").toIntExact(),
            cpuRows = num("ROWS").toIntExact(),
            pairs = num("PAIRS").toIntExact(),
            rounds = num("ROUNDS").toIntExact(),
            profile = num("PROFILE").toIntExact(),
            writesPerBatch = num("WRITES").toIntExact(),
            lookupsA = num("LOOKUPS_A"),
            lookupsB = num("LOOKUPS_B"),
            batchesA = batches("BATCH_A"),
            batchesB = batches("BATCH_B"),
            medianANs = num("MEDIAN_A_NS"),
            medianBNs = num("MEDIAN_B_NS"),
            pairedDeltaNs = num("MEDIAN_DELTA_NS"),
            childEnd = num("CHILD_END").toIntExact(),
        )
        require(snapshot.pairs in 0..128 && snapshot.rounds in 0..4 && snapshot.profile in 0..3 && snapshot.cpuRows in 0..256 &&
            snapshot.lookupsA >= 0 && snapshot.lookupsB >= 0 &&
            snapshot.medianANs >= 0 && snapshot.medianBNs >= 0) { "Invalid AVC lookup counts" }
        require(snapshot.batchesA.size == 4 && snapshot.batchesB.size == 4 &&
            snapshot.batchesA.all { it in 0..UINT_MAX } && snapshot.batchesB.all { it in 0..UINT_MAX }) {
            "Malformed per-round AVC counts"
        }
        if (state == SelinuxAvcLookupState.COLLECTED) {
            require(snapshot.error == 0 && snapshot.statsError == 0 && snapshot.childEnd == 2 &&
                snapshot.rounds == 4 && snapshot.pairs == 128 && snapshot.writesPerBatch == 4096 &&
                snapshot.cpu in 0 until snapshot.cpuRows &&
                snapshot.batchesA.sum() == snapshot.lookupsA && snapshot.batchesB.sum() == snapshot.lookupsB) {
                "Incomplete AVC measurement"
            }
        }
        return snapshot
    }

    // Restores only data actually observed in app_zygote. Legacy snapshots
    // without this field remain NOT_COLLECTED rather than becoming negatives.
    fun encode(s: SelinuxAvcLookupSnapshot): String = buildString {
        append("SCHEMA=1\nSTATE=${s.state.name}\nERROR=${s.error}\nSTATS_ERROR=${s.statsError}\n")
        append("CPU=${s.cpu}\nROWS=${s.cpuRows}\nPAIRS=${s.pairs}\nROUNDS=${s.rounds}\nPROFILE=${s.profile}\n")
        append("WRITES=${s.writesPerBatch}\nLOOKUPS_A=${s.lookupsA}\nLOOKUPS_B=${s.lookupsB}\n")
        append("BATCH_A=${(s.batchesA.ifEmpty { List(4) { 0L } }).joinToString(",")}\n")
        append("BATCH_B=${(s.batchesB.ifEmpty { List(4) { 0L } }).joinToString(",")}\n")
        append("MEDIAN_A_NS=${s.medianANs}\nMEDIAN_B_NS=${s.medianBNs}\n")
        append("MEDIAN_DELTA_NS=${s.pairedDeltaNs}\nCHILD_END=${s.childEnd}\n")
    }

    private fun Long.toIntExact(): Int = toInt().also { require(it.toLong() == this) }
    private const val UINT_MAX = 4294967295L
}
