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

package com.eltavine.duckdetector.features.dangerousapps.data.probes.hma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class HmaUidTaskBridgeTest {
    @Test fun `raw syscall priorities use the kernel offset rather than libc return semantics`() {
        val result = HmaUidTaskBridge.parse(intArrayOf(1, 0, 2, 0, 20, 2, 10000, 40, 10001, 1), 10000, 10001)
        assertEquals(mapOf(10000 to -20, 10001 to 19), result.tasks)
    }

    @Test fun `partial collection keeps its scope`() {
        val result = HmaUidTaskBridge.parse(intArrayOf(1, 1, 16, 0, 20, 0), 10000, 19999)
        assertEquals(HmaUidTaskBridge.PARTIAL, result.status)
        assertEquals(16, result.checked)
    }

    @Test fun `permission and child failures retain an error without becoming empty success`() {
        val result = HmaUidTaskBridge.parse(intArrayOf(1, 2, 0, 1, 0, 0), 10000, 19999)
        assertEquals(HmaUidTaskBridge.RESTRICTED, result.status)
        assertEquals(1, result.error)
    }

    @Test fun `reject corrupt counts priorities scope duplicate UIDs and incomplete success`() {
        val invalid = listOf(
            intArrayOf(2, 0, 1, 0, 20, 0),
            intArrayOf(1, 0, 0, 0, 20, 0),
            intArrayOf(1, 0, 1, 0, 20, 1, 10000, 0),
            intArrayOf(1, 0, 1, 0, 20, 1, 10001, 20),
            intArrayOf(1, 0, 1, 0, 20, 2, 10000, 20, 10000, 20),
            intArrayOf(1, 0, 1, 0, 20, -1),
        )
        for (values in invalid) assertThrows(IllegalArgumentException::class.java) {
            HmaUidTaskBridge.parse(values, 10000, 10000)
        }
    }

    @Test fun `partial payload cannot claim unvisited UIDs or ignore a collection error`() {
        for (values in listOf(intArrayOf(1, 1, 1, 0, 20, 1, 10001, 20),
            intArrayOf(1, 1, 1, 5, 20, 0))) {
            assertThrows(IllegalArgumentException::class.java) {
                HmaUidTaskBridge.parse(values, 10000, 19999)
            }
        }
    }

    @Test fun `native observations must retain ascending scan order`() {
        assertThrows(IllegalArgumentException::class.java) {
            HmaUidTaskBridge.parse(intArrayOf(1, 0, 2, 0, 20, 2, 10001, 20, 10000, 20), 10000, 10001)
        }
    }
}
