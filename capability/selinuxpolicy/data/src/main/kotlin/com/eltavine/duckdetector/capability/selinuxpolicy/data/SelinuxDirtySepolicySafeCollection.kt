package com.eltavine.duckdetector.capability.selinuxpolicy.data

/** A failing optional Raw replay must never discard completed legacy App Zygote evidence. */
internal fun collectDirtySepolicyRawSafely(
    original: SelinuxContextValiditySnapshot,
    collect: () -> SelinuxDirtySepolicyRawSnapshot,
): SelinuxContextValiditySnapshot {
    val result = try {
        collect()
    } catch (error: Throwable) {
        val reason = "DirtySepolicy Raw replay failed: ${error.message?.takeIf(String::isNotBlank) ?: "unknown cause"}"
        SelinuxDirtySepolicyRawSnapshot(
            state = SelinuxDirtySepolicyRawState.UNAVAILABLE,
            failureReason = reason,
            compatibility = SelinuxDirtySepolicyCompatibilityResult(
                SelinuxDirtySepolicyCompatibilityVerdict.ERROR,
                listOf(reason),
            ),
        )
    }
    return original.copy(dirtySepolicyRaw = result)
}
