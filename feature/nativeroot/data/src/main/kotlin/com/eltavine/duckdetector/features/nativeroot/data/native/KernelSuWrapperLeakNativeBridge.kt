package com.eltavine.duckdetector.features.nativeroot.data.native

import com.eltavine.duckdetector.core.native.NativeSnapshotCollector
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuWrapperLeakObservation
import com.eltavine.duckdetector.features.nativeroot.domain.WrapperFileNrPoint
import com.eltavine.duckdetector.features.nativeroot.domain.WrapperLeakCollection

internal class KernelSuWrapperLeakNativeBridge(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
) {
    fun collect(): KernelSuWrapperLeakObservation = collector.collect(
        readPayload = ::nativeCollect,
        parse = ::parse,
        unavailable = { KernelSuWrapperLeakObservation(collection = WrapperLeakCollection.UNAVAILABLE, detail = "${it.outcome}: ${it.detail}") },
    )

    internal fun parse(raw: LongArray): KernelSuWrapperLeakObservation {
        require(raw.size in 6..34 && raw[0] == 1L)
        require(raw[1] in 0..8)
        val stage = requireNotNull(WrapperLeakCollection.entries.singleOrNull { it.wireCode.toLong() == raw[1] })
        require(raw[2] in 0..Int.MAX_VALUE.toLong() && raw[3] in 0..3 && raw[4] in 0..768 && raw[5] in 0..14)
        require(raw.size.toLong() == 6 + raw[5] * 2)
        val points = raw.drop(6).chunked(2).map {
            require(it[0] > 0 && it[1] >= 0)
            WrapperFileNrPoint(it[0], it[1])
        }
        val rounds = raw[3].toInt()
        val reopens = raw[4].toInt()
        val count = points.size
        // A target batch starts after baseline/idle/direct points, and adds its point only
        // after all 256 reopens complete. Failed final points may still consume that batch.
        require(reopens in (count / 4).coerceAtMost(3) * 256..((count + 1) / 4).coerceAtMost(3) * 256)
        require(rounds * 256 <= reopens)
        require(count >= if (rounds == 0) 0 else rounds * 4 + 1)
        require(count <= (rounds * 4 + 5).coerceAtMost(14))
        if (stage == WrapperLeakCollection.NO_CANDIDATE)
            require(raw[2] == 0L && rounds == 0 && reopens == 0 && count == 0)
        if (stage == WrapperLeakCollection.NOISY_CONTROLS) require(raw[2] == 0L && count > 0)
        if (stage == WrapperLeakCollection.COLLECTED)
            require(raw[2] == 0L && raw[3] == 3L && raw[4] == 768L && points.size == 14)
        return KernelSuWrapperLeakObservation(stage, raw[2].toInt(), raw[3].toInt(), raw[4].toInt(), points)
    }
    private external fun nativeCollect(): LongArray
}
