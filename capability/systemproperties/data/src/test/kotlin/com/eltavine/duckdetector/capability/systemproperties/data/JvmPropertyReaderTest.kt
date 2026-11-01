/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.capability.systemproperties.data

import org.junit.Assert.*
import org.junit.Test

class JvmPropertyReaderTest {
    @Test fun `reads are fresh and absence differs from invalid-key failure`() {
        val key = "duckdetector.test.jvm_property"
        val previous = System.getProperty(key)
        try {
            System.clearProperty(key)
            assertTrue(readJvmProperty(key).isSuccess)
            assertNull(readJvmProperty(key).getOrThrow())
            System.setProperty(key, "first")
            assertEquals("first", readJvmProperty(key).getOrThrow())
            System.setProperty(key, "second")
            assertEquals("second", readJvmProperty(key).getOrThrow())
            assertTrue(readJvmProperty("").isFailure)
        } finally {
            if (previous == null) System.clearProperty(key) else System.setProperty(key, previous)
        }
    }
}
