package com.eltavine.duckdetector.features.nativeroot.presentation

import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuWrapperLeakObservation
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethod
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodOutcome
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodResult
import com.eltavine.duckdetector.features.nativeroot.domain.WrapperLeakCollection
import com.eltavine.duckdetector.features.nativeroot.domain.WrapperLeakVerdict

fun wrapperLeakMethod(observation: KernelSuWrapperLeakObservation): NativeRootMethodResult {
    val matched = observation.verdict == WrapperLeakVerdict.REPEATED_GROWTH
    return NativeRootMethodResult(
        NativeRootMethod.KSU_WRAPPER_REFERENCE_LEAK,
        when {
            matched -> "Repeated file-object growth"
            observation.collection == WrapperLeakCollection.NOT_REQUESTED -> "Not evaluated"
            observation.collection == WrapperLeakCollection.NO_CANDIDATE -> "No wrapper candidate; not evaluated"
            observation.collection == WrapperLeakCollection.PERMISSION_LIMITED -> "Permission limited"
            observation.verdict == WrapperLeakVerdict.NO_PATTERN -> "Leak pattern not observed"
            observation.verdict == WrapperLeakVerdict.INCONCLUSIVE -> "Inconclusive"
            else -> "Unavailable: ${observation.collection}"
        },
        if (matched) NativeRootMethodOutcome.WARNING else NativeRootMethodOutcome.SUPPORT,
        buildString {
            append("Reopens an existing anonymous-inode PTY wrapper through /proc/self/fd, interleaving idle and direct-terminal controls. ")
            append("file-nr is system-wide and approximate; repeated growth is supporting evidence, not KSU or root identification. ")
            append("KernelSU PR #3958 fixes the reference imbalance. A patched wrapper, a missing candidate or restricted procfs cannot exclude KSU. ")
            append("No root request is made. At most 768 wrapped reopens run once per scanner instance; results are reused on later scans, and a new scanner has a new budget. ")
            append("On affected kernels, pinned file objects can persist after descriptors close and after process exit. ")
            append("Thresholds are provisional and have not been calibrated across devices.\n")
            append("collection=${observation.collection}; errno=${observation.error}; rounds=${observation.completedRounds}; reopens=${observation.reopens}\n")
            append("Points: baseline, then [idle, direct, reopen, direct] x3, persistence. Values are median/spread.\n")
            append(observation.points.joinToString("; ") { "${it.median}/${it.spread}" })
            if (observation.detail.isNotBlank()) append("\n${observation.detail}")
        },
    )
}
