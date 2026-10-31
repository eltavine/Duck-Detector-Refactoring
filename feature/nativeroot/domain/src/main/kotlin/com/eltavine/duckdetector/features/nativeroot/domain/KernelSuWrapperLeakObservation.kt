package com.eltavine.duckdetector.features.nativeroot.domain

enum class WrapperLeakCollection(val wireCode: Int) {
    COLLECTED(0), NO_CANDIDATE(1), UNAVAILABLE(2), PERMISSION_LIMITED(3), MALFORMED_COUNTER(4),
    IO_FAILED(5), TIMED_OUT(6), CLEANUP_FAILED(7), NOISY_CONTROLS(8), NOT_REQUESTED(-1),
}
enum class WrapperLeakVerdict { REPEATED_GROWTH, NO_PATTERN, INCONCLUSIVE, NOT_EVALUATED }
data class WrapperFileNrPoint(val median: Long, val spread: Long)

data class KernelSuWrapperLeakObservation(
    val collection: WrapperLeakCollection = WrapperLeakCollection.NOT_REQUESTED,
    val error: Int = 0,
    val completedRounds: Int = 0,
    val reopens: Int = 0,
    val points: List<WrapperFileNrPoint> = emptyList(),
    val detail: String = "",
) {
    val verdict: WrapperLeakVerdict
        get() {
            if (collection == WrapperLeakCollection.NOISY_CONTROLS) return WrapperLeakVerdict.INCONCLUSIVE
            if (collection != WrapperLeakCollection.COLLECTED) return WrapperLeakVerdict.NOT_EVALUATED
            if (error != 0 || completedRounds != 3 || reopens != 768 || points.size != 14 ||
                points.any { it.median <= 0 || it.spread !in 0..64 }) return WrapperLeakVerdict.INCONCLUSIVE
            val deltas = points.zipWithNext { a, b -> b.median - a.median }
            val controls = listOf(0, 1, 3, 4, 5, 7, 8, 9, 11, 12)
            if (controls.any { deltas[it] !in -64..64 }) return WrapperLeakVerdict.INCONCLUSIVE
            val growth = listOf(deltas[2], deltas[6], deltas[10])
            // Provisional conservative bounds around one pinned file per successful reopen.
            // System-wide counters cannot establish causal attribution to KernelSU.
            if (growth.all { it in 192..320 } &&
                growth.sum() in 640..896 &&
                points.last().median - points.first().median in 576..960)
                return WrapperLeakVerdict.REPEATED_GROWTH
            return if (growth.all { it in -64..64 }) WrapperLeakVerdict.NO_PATTERN
                else WrapperLeakVerdict.INCONCLUSIVE
        }
}
