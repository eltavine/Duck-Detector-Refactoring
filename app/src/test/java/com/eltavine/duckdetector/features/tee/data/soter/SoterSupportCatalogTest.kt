/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
