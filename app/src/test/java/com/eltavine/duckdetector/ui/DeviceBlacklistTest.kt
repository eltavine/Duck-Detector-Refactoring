package com.eltavine.duckdetector.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DeviceBlacklistTest {

    @Test
    fun `huawei manufacturer is blocked`() {
        val match = DeviceBlacklist.match(
            manufacturer = "HUAWEI",
            brand = "Huawei",
        )

        requireNotNull(match)
        assertEquals("HUAWEI devices are not supported.", match.message)
    }

    @Test
    fun `huawei brand is blocked`() {
        val match = DeviceBlacklist.match(
            manufacturer = "Honor",
            brand = "huawei",
        )

        requireNotNull(match)
        assertEquals("Honor", match.manufacturer)
    }

    @Test
    fun `non huawei device is allowed`() {
        val match = DeviceBlacklist.match(
            manufacturer = "Google",
            brand = "google",
        )

        assertNull(match)
    }
}
