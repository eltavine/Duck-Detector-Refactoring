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
        val stage = WrapperLeakCollection.entries.getOrNull(raw[1].toInt())
        require(stage != null && raw[1] in 0..8 && raw[1] == stage.ordinal.toLong())
        require(raw[2] in 0..Int.MAX_VALUE.toLong() && raw[3] in 0..3 && raw[4] in 0..768 && raw[5] in 0..14)
        require(raw.size.toLong() == 6 + raw[5] * 2)
        val points = raw.drop(6).chunked(2).map {
            require(it[0] > 0 && it[1] >= 0)
            WrapperFileNrPoint(it[0], it[1])
        }
        if (stage == WrapperLeakCollection.COLLECTED)
            require(raw[2] == 0L && raw[3] == 3L && raw[4] == 768L && points.size == 14)
        return KernelSuWrapperLeakObservation(stage, raw[2].toInt(), raw[3].toInt(), raw[4].toInt(), points)
    }
    private external fun nativeCollect(): LongArray
}
