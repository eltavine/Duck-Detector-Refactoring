// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.features.dangerousapps.domain

enum class ThanoxIpcState {
    NOT_COLLECTED,
    NOT_OBSERVED,
    MATCHED,
    UNAVAILABLE,
    INCONCLUSIVE,
}

/** Runtime protocol evidence, independent of package installation and visibility. */
data class ThanoxIpcReport(
    val state: ThanoxIpcState,
    val observedDescriptor: String? = null,
    val detail: String? = null,
) {
    val complete: Boolean
        get() = state == ThanoxIpcState.NOT_OBSERVED || state == ThanoxIpcState.MATCHED
}
