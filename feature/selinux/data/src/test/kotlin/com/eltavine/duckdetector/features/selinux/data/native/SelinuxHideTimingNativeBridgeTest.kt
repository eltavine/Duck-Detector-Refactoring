/*
 * Copyright 2026 Duck Apps Contributor
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package com.eltavine.duckdetector.features.selinux.data.native

import com.eltavine.duckdetector.features.selinux.data.probes.buildSelinuxHideTimingMethod
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxHideTimingNativeBridgeTest {
    private val bridge = SelinuxHideTimingNativeBridge()

    private fun payload(state: String, median: Long = 885) = """
        STATE=$state
        PAIRS=256
        A_MEDIAN_NS=2500
        B_MEDIAN_NS=1615
        DELTA_P10_NS=729
        DELTA_MEDIAN_NS=$median
        DELTA_P90_NS=991
        HALVES_NS=860,910
        A_SLOWER=253
        CONTEXT_LENGTH=40
        ERRORS=both EACCES
    """.trimIndent()

    @Test fun `candidate remains a supporting signal rather than a confirmed root finding`() {
        val parsed = bridge.parse(payload("CANDIDATE"))
        val result = buildSelinuxHideTimingMethod(parsed)
        assertEquals(SelinuxHideTimingState.CANDIDATE, parsed.state)
        assertEquals(885L, parsed.deltaMedianNs)
        assertEquals(false, result.isSecure)
        assertTrue(result.status.contains("experimental"))
        assertTrue(result.details.orEmpty().contains("not proof of KernelSU"))
    }

    @Test fun `no signal cannot claim clean or no root`() {
        val parsed = bridge.parse(payload("NO_SIGNAL", 0))
        val result = buildSelinuxHideTimingMethod(parsed)
        assertNull(result.isSecure)
        assertTrue(result.details.orEmpty().contains("cannot rule out"))
    }

    @Test fun `missing or inconsistent denial contract is rejected`() {
        listOf("STATE=CANDIDATE", payload("CANDIDATE").replace("ERRORS=both EACCES", "ERRORS=success"))
            .forEach { raw ->
                val thrown = runCatching { bridge.parse(raw) }.exceptionOrNull()
                assertTrue(thrown is IllegalArgumentException)
            }
    }

    @Test fun `unavailable preserves the concrete failure`() {
        val parsed = bridge.parse("STATE=UNAVAILABLE\nREASON=B preflight unexpected open_errno=13")
        assertEquals(SelinuxHideTimingState.UNAVAILABLE, parsed.state)
        assertTrue(parsed.reason.orEmpty().contains("open_errno=13"))
        assertFalse(buildSelinuxHideTimingMethod(parsed).isSecure == true)
    }
}
