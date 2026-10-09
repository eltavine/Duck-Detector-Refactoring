/*
 * Copyright 2026 Duck Apps Contributor
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.features.selinux.data.native.SelinuxHideTimingNativeBridge
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxHideTimingSnapshot
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxHideTimingState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle

internal fun buildSelinuxHideTimingMethod(result: SelinuxHideTimingSnapshot): SelinuxCheckResult {
    val state = result.state
    val details = if (state == SelinuxHideTimingState.UNAVAILABLE) {
        result.reason ?: "The ordinary-app probe could not run"
    } else buildString {
        append("/proc/thread-self/attr/current | native ordinary-app thread | ")
        append("A=self valid context; B=same length with leading newline; both write()=-EACCES.\n")
        append("Pairs=${result.pairs}; A median=${result.aMedianNs} ns; B median=${result.bMedianNs} ns; ")
        append("paired A-B p10/median/p90=${result.deltaP10Ns}/${result.deltaMedianNs}/${result.deltaP90Ns} ns; ")
        append("half medians=${result.firstHalfNs}/${result.secondHalfNs} ns; ")
        append("A slower=${result.aSlower}/${result.pairs}; context bytes=${result.contextLength}.\n")
        append("This is a device-dependent timing clue, not proof of KernelSU. ")
        append("A clean result cannot rule out SELinux Hide, earlier KSU revisions or other root methods. ")
        append("Observed on Android 14/GKI 5.15 with KernelSU df03912f; not reproduced on Android 17/GKI 6.12.")
    }
    return SelinuxCheckResult(
        method = SelinuxOracle.ATTR_CURRENT_TIMING.label,
        status = when (state) {
            SelinuxHideTimingState.CANDIDATE -> "Timing asymmetry (experimental)"
            SelinuxHideTimingState.NO_SIGNAL -> "No reproducible asymmetry"
            SelinuxHideTimingState.UNAVAILABLE -> "Unavailable"
        },
        isSecure = if (state == SelinuxHideTimingState.CANDIDATE) false else null,
        permissionDenied = false,
        details = details,
        oracle = SelinuxOracle.ATTR_CURRENT_TIMING,
    )
}
