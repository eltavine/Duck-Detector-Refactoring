package com.eltavine.duckdetector.features.tee.data.verification.keystore

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TimingSideChannelThresholdTest {

    @Test
    fun `diff above 0_2ms is positive`() {
        assertTrue(isPositiveTimingSideChannelDiff(diffMillis = 0.2001))
    }

    @Test
    fun `diff below minus 0_2ms is positive`() {
        assertTrue(isPositiveTimingSideChannelDiff(diffMillis = -0.2001))
    }

    @Test
    fun `diff equal to 0_2ms is not positive`() {
        assertFalse(isPositiveTimingSideChannelDiff(diffMillis = 0.2))
    }

    @Test
    fun `diff equal to minus 0_2ms is not positive`() {
        assertFalse(isPositiveTimingSideChannelDiff(diffMillis = -0.2))
    }

    @Test
    fun `diff inside symmetric threshold is not positive`() {
        assertFalse(isPositiveTimingSideChannelDiff(diffMillis = 0.1999))
    }

    private fun isPositiveTimingSideChannelDiff(diffMillis: Double): Boolean {
        return diffMillis > 0.2 || diffMillis < -0.2
    }
}
