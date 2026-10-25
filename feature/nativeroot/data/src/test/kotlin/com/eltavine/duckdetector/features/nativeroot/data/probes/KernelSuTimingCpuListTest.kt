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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class KernelSuTimingCpuListTest {
    @Test fun `CPU lists preserve sparse IDs and ranges`() {
        assertEquals(listOf(0, 1, 2, 5, 9, 10), KernelSuTimingCpuList.parse("0-2,5,9-10\n"))
        assertEquals(emptyList<Int>(), KernelSuTimingCpuList.parse("\n"))
        assertEquals(listOf(1023), KernelSuTimingCpuList.parse("1023"))
    }
    @Test fun `malformed duplicate unordered and out of range inventories are unavailable`() {
        for (raw in listOf("0-", "-1", "3-1", "0,0", "1,0", "0,", "1024", "0-999999", "0 1")) {
            assertThrows(IllegalArgumentException::class.java) { KernelSuTimingCpuList.parse(raw) }
        }
    }
}
