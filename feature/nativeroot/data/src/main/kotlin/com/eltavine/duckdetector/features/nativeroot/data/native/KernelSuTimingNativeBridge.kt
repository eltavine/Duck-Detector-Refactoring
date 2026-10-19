package com.eltavine.duckdetector.features.nativeroot.data.native

import com.eltavine.duckdetector.core.native.DuckDetectorNativeLibrary
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreStatus
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingProfile

internal data class KernelSuTimingWindow(
    val status: KernelSuTimingCoreStatus?,
    val actualCpu: Int?,
    val frequency: ULong,
    val cleanup: Boolean,
    val vectors: List<List<ULong>>,
)

internal class KernelSuTimingNativeBridge {
    fun sample(cpu: Int, preflight: Boolean): KernelSuTimingWindow {
        check(DuckDetectorNativeLibrary.isLoaded) { "Native library unavailable" }
        return parse(nativeSample(cpu, preflight), preflight)
    }

    internal fun parse(raw: LongArray, preflight: Boolean): KernelSuTimingWindow {
        require(raw.size in 4..60004)
        require(raw[0] in 0L..6L && raw[1] in -1L..1023L && raw[3] in 0L..1L)
        val status = raw[0].toInt()
        val expected = if (preflight) KernelSuTimingProfile.SAMPLE_COUNT else 6 * KernelSuTimingProfile.SAMPLE_COUNT
        require(raw.size == if (status == 0) expected + 4 else 4)
        require(status != 0 || (raw[2] != 0L && raw[1] >= 0 && raw[3] == 1L))
        return KernelSuTimingWindow(KernelSuTimingCoreStatus.entries.getOrNull(status),
            raw[1].toInt().takeIf { it >= 0 }, raw[2].toULong(), raw[3] == 1L,
            raw.drop(4).map { it.toULong() }.chunked(KernelSuTimingProfile.SAMPLE_COUNT))
    }

    private external fun nativeSample(cpu: Int, preflight: Boolean): LongArray
}
