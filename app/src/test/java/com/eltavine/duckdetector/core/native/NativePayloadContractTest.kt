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

package com.eltavine.duckdetector.core.native

import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class NativePayloadContractTest {

    @Test
    fun `accepts a payload that carries every required key`() {
        NativePayloadContract.requireKeys("AVAILABLE=1\nROOT_FOUND=0\n", "AVAILABLE")
    }

    @Test
    fun `ignores keys it was not asked about so a newer native layer stays readable`() {
        NativePayloadContract.requireKeys(
            "AVAILABLE=1\nKEY_ADDED_BY_A_LATER_BUILD=1\nFINDING=a\tb\n",
            "AVAILABLE",
        )
    }

    @Test
    fun `rejects a payload whose required key was renamed`() {
        val violation = assertThrows(NativePayloadContractViolation::class.java) {
            NativePayloadContract.requireKeys("IS_AVAILABLE=1\nROOT_FOUND=0\n", "AVAILABLE")
        }

        assertTrue(violation.message!!.contains("AVAILABLE"))
    }

    @Test
    fun `names every missing key so a reader can tell how far the contract drifted`() {
        val violation = assertThrows(NativePayloadContractViolation::class.java) {
            NativePayloadContract.requireKeys("ROOT_FOUND=0\n", "AVAILABLE", "SUPPORTED")
        }

        assertTrue(violation.message!!.contains("AVAILABLE"))
        assertTrue(violation.message!!.contains("SUPPORTED"))
    }

    @Test
    fun `reads a key only from the left of the first separator`() {
        NativePayloadContract.requireKeys("AVAILABLE=a=b\n", "AVAILABLE")
    }

    @Test
    fun `ignores records that carry no separator`() {
        val violation = assertThrows(NativePayloadContractViolation::class.java) {
            NativePayloadContract.requireKeys("AVAILABLE\n", "AVAILABLE")
        }

        assertTrue(violation.message!!.contains("AVAILABLE"))
    }

    @Test
    fun `ignores a record that opens with the separator`() {
        val violation = assertThrows(NativePayloadContractViolation::class.java) {
            NativePayloadContract.requireKeys("=1\n", "AVAILABLE")
        }

        assertTrue(violation.message!!.contains("AVAILABLE"))
    }

    @Test
    fun `asks nothing of a payload when no key was named`() {
        NativePayloadContract.requireKeys("anything at all")
    }
}
