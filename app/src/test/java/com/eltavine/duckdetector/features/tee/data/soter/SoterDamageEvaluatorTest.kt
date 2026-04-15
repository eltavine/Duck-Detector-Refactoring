package com.eltavine.duckdetector.features.tee.data.soter

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SoterDamageEvaluatorTest {

    private val evaluator = SoterDamageEvaluator()

    @Test
    fun `service failure skips probe without warning`() {
        val state = evaluator.evaluate(
            serviceReachable = false,
            keyPrepared = false,
            signSessionAvailable = false,
            errorMessage = "skipped",
        )

        assertFalse(state.serviceReachable)
        assertFalse(state.damaged)
        assertTrue(state.summary.contains("soter", ignoreCase = true))
        assertTrue(state.summary.contains("skipped", ignoreCase = true))
    }

    @Test
    fun `key or signing failure becomes damaged`() {
        val state = evaluator.evaluate(
            serviceReachable = true,
            keyPrepared = true,
            signSessionAvailable = false,
            errorMessage = "sign failed",
        )

        assertFalse(state.available)
        assertTrue(state.damaged)
        assertTrue(state.summary.contains("soter", ignoreCase = true))
    }

    @Test
    fun `successful sequence stays available`() {
        val state = evaluator.evaluate(
            serviceReachable = true,
            keyPrepared = true,
            signSessionAvailable = true,
            errorMessage = null,
        )

        assertTrue(state.available)
        assertFalse(state.damaged)
        assertTrue(state.summary.contains("soter", ignoreCase = true))
    }

    @Test
    fun `abnormal environment stays warning without damage`() {
        val state = evaluator.evaluate(
            serviceReachable = false,
            keyPrepared = false,
            signSessionAvailable = false,
            errorMessage = "skipped",
            abnormalEnvironment = true,
        )

        assertFalse(state.available)
        assertFalse(state.damaged)
        assertTrue(state.abnormalEnvironment)
        assertTrue(state.summary.contains("abnormal soter environment", ignoreCase = true))
    }
}
