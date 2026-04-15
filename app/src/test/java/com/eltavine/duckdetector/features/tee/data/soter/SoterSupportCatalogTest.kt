package com.eltavine.duckdetector.features.tee.data.soter

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SoterSupportCatalogTest {

    private val catalog = SoterSupportCatalog()

    @Test
    fun `known soter brands are recognized from manufacturer or brand`() {
        assertTrue(catalog.expectsSupport(manufacturer = "Xiaomi", brand = "Redmi"))
        assertTrue(catalog.expectsSupport(manufacturer = "motorola", brand = "moto"))
        assertTrue(catalog.expectsSupport(manufacturer = "unknown", brand = "iQOO"))
    }

    @Test
    fun `unsupported brands stay outside the catalog`() {
        assertFalse(catalog.expectsSupport(manufacturer = "Google", brand = "Pixel"))
        assertFalse(catalog.expectsSupport(manufacturer = "Nothing", brand = "Phone"))
    }
}
