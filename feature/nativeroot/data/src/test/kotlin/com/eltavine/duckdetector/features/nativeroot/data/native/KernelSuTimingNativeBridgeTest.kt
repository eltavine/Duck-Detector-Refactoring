package com.eltavine.duckdetector.features.nativeroot.data.native

import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class KernelSuTimingNativeBridgeTest {
    private val bridge = KernelSuTimingNativeBridge()

    @Test fun `unsigned ticks and frequency retain all bits`() {
        val raw = longArrayOf(0, 2, -1, 1) + LongArray(60000) { -1 }
        val result = bridge.parse(raw, false)
        assertEquals(ULong.MAX_VALUE, result.frequency)
        assertEquals(ULong.MAX_VALUE, result.vectors.last().last())
        assertEquals(KernelSuTimingCoreStatus.MEASURED, result.status)
        assertEquals(2, result.actualCpu)
    }

    @Test fun `malformed and inconsistent windows are rejected`() {
        for (raw in listOf(longArrayOf(), longArrayOf(0, 0, 1, 1), longArrayOf(7, 0, 1, 1),
            longArrayOf(1, 0, 1, 2), longArrayOf(1, 0, 1, 1, 0),
            longArrayOf(0, 0, 0, 1) + LongArray(10000),
            longArrayOf(0, -1, 1, 1) + LongArray(10000),
            longArrayOf(0, 0, 1, 0) + LongArray(10000))) {
            assertThrows(IllegalArgumentException::class.java) { bridge.parse(raw, true) }
        }
    }

    @Test fun `unsupported has no samples and preflight accepts only one vector`() {
        assertEquals(null, bridge.parse(longArrayOf(6, -1, 0, 1), true).status)
        val raw = longArrayOf(0, 0, 1, 1) + LongArray(10000)
        assertEquals(1, bridge.parse(raw, true).vectors.size)
        assertThrows(IllegalArgumentException::class.java) { bridge.parse(raw, false) }
    }
}
