// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.features.mount.domain

/** Coverage of an anonymous-device observation, independent of root attribution. */
enum class MountAnonymousDeviceState(
    val summary: String,
    val coverageLimited: Boolean,
) {
    NOT_COLLECTED("Unavailable", true),
    UNAVAILABLE("Unavailable", true),
    UNSUPPORTED("Unsupported", true),
    INCONCLUSIVE("Inconclusive", true),
    PARTIAL("Partial", true),
    OBSERVED("Gaps observed", false),
    NO_GAPS("No gaps observed", false),
}
