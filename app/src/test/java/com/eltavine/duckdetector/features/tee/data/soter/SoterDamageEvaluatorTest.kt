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
        assertFalse(state.warning)
        assertTrue(state.summary.contains("skipped", ignoreCase = true))
    }

    @Test
    fun `key or signing failure becomes warning`() {
        val state = evaluator.evaluate(
            serviceReachable = true,
            keyPrepared = true,
            signSessionAvailable = false,
            errorMessage = "sign failed",
        )

        assertFalse(state.available)
        assertTrue(state.warning)
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
        assertFalse(state.warning)
    }
}
