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

package com.eltavine.duckdetector.features.selinux.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxContextValidityPayloadCodecTest {

    private val bridge = SelinuxContextValidityBridge()

    @Test
    fun `encode round trips through parser`() {
        val snapshot = SelinuxContextValiditySnapshot(
            available = true,
            probeAttempted = true,
            carrierContext = "u:r:app_zygote:s0:c1,c2",
            carrierMatchesExpected = true,
            carrierControlValid = true,
            negativeControlRejected = true,
            fileControlValid = true,
            fileNegativeControlRejected = true,
            oracleControlsPassed = true,
            ksuResultsStable = true,
            queryMethod = "raw selinuxfs write",
            ksuDomainValid = true,
            ksuFileValid = false,
            bitPair = "11",
            failureReason = "Carrier\ncontext unavailable",
            notes = listOf(
                "Carrier context: u:r:app_zygote:s0",
                "Query\tmethod\nraw selinuxfs write",
            ),
        )

        val parsed = bridge.parse(SelinuxContextValidityPayloadCodec.encode(snapshot))

        assertTrue(parsed.available)
        assertTrue(parsed.probeAttempted)
        assertEquals(snapshot.carrierContext, parsed.carrierContext)
        assertTrue(parsed.carrierMatchesExpected)
        assertTrue(parsed.carrierControlValid == true)
        assertTrue(parsed.negativeControlRejected == true)
        assertTrue(parsed.fileControlValid == true)
        assertTrue(parsed.fileNegativeControlRejected == true)
        assertTrue(parsed.oracleControlsPassed)
        assertTrue(parsed.ksuResultsStable)
        assertEquals(snapshot.queryMethod, parsed.queryMethod)
        assertTrue(parsed.ksuDomainValid == true)
        assertTrue(parsed.ksuFileValid == false)
        assertEquals(snapshot.bitPair, parsed.bitPair)
        assertEquals(snapshot.failureReason, parsed.failureReason)
        assertEquals(snapshot.notes, parsed.notes)
    }
}
