package com.eltavine.duckdetector.features.nativeroot.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import com.eltavine.duckdetector.features.nativeroot.domain.WrapperLeakVerdict
import com.eltavine.duckdetector.features.nativeroot.domain.WrapperLeakCollection

class KernelSuWrapperLeakNativeBridgeTest {
    private val bridge = KernelSuWrapperLeakNativeBridge()
    private fun payload() = longArrayOf(1, 0, 0, 3, 768, 14) + LongArray(28) { if (it % 2 == 0) 10000 else 0 }
    @Test fun `complete payload maps to evaluated absence of this pattern only`() {
        assertEquals(WrapperLeakVerdict.NO_PATTERN, bridge.parse(payload()).verdict)
    }
    @Test fun `malformed native data never becomes a clean result`() {
        val good = payload()
        val invalid = listOf(good.dropLast(1).toLongArray(), good + 0L,
            good.copyOf().apply { this[0] = 2 }, good.copyOf().apply { this[1] = 1L shl 32 },
            good.copyOf().apply { this[2] = -1 }, good.copyOf().apply { this[3] = 2 },
            good.copyOf().apply { this[4] = 769 }, good.copyOf().apply { this[5] = 13 },
            good.copyOf().apply { this[6] = 0 }, good.copyOf().apply { this[7] = -1 })
        invalid.forEach { raw -> assertThrows(IllegalArgumentException::class.java) { bridge.parse(raw) } }
    }
    @Test fun `impossible partial progress and no-candidate payloads are rejected`() {
        val cases = listOf(
            longArrayOf(1, 1, 0, 0, 1, 0),
            longArrayOf(1, 1, 13, 0, 0, 0),
            longArrayOf(1, 5, 5, 1, 256, 0),
            longArrayOf(1, 5, 5, 0, 0, 4) + LongArray(8) { if (it % 2 == 0) 10000 else 0 },
            longArrayOf(1, 8, 0, 0, 0, 0),
            longArrayOf(1, -1, 0, 0, 0, 0),
        )
        cases.forEach { raw -> assertThrows(IllegalArgumentException::class.java) { bridge.parse(raw) } }
    }
    @Test fun `partial target consumption without its final point remains explicit`() {
        val raw = longArrayOf(1, 5, 5, 0, 17, 3) + LongArray(6) { if (it % 2 == 0) 10000 else 0 }
        val observation = bridge.parse(raw)
        assertEquals(WrapperLeakCollection.IO_FAILED, observation.collection)
        assertEquals(17, observation.reopens)
        assertEquals(WrapperLeakVerdict.NOT_EVALUATED, observation.verdict)
    }
}
