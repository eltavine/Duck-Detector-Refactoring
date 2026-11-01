// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.features.zygisk.domain

enum class ZygiskAtexitState(val label: String) {
    NOT_COLLECTED("Not collected"),
    COLLECTED("Evaluated"),
    UNSUPPORTED("Unsupported"),
    UNAVAILABLE("Unavailable"),
    PERMISSION_DENIED("Permission limited"),
    BUSY("Busy"),
    INVALID("Invalid layout"),
    PARTIAL("Partially evaluated"),
}

data class ZygiskAtexitObservation(
    val state: ZygiskAtexitState = ZygiskAtexitState.NOT_COLLECTED,
    val dumpable: Int = -1,
    val entries: Int = 0,
    val nullEntries: Int = 0,
    val anchoredGaps: Int = 0,
    val anonymousCallbacks: Int = 0,
    val detail: String = "Exit-handler table was not evaluated.",
) {
    val hasEvidence: Boolean get() = anchoredGaps > 0 || anonymousCallbacks > 0
}
