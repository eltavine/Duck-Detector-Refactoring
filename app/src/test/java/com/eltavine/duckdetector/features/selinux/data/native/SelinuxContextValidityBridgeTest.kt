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

class SelinuxContextValidityBridgeTest {

    private val bridge = SelinuxContextValidityBridge()

    @Test
    fun `parse decodes context validity snapshot`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                PROBE_ATTEMPTED=1
                CARRIER_CONTEXT=u:r:app_zygote:s0:c1,c2
                CARRIER_MATCHES_EXPECTED=1
                CARRIER_CONTROL_VALID=1
                NEGATIVE_CONTROL_REJECTED=1
                FILE_CONTROL_VALID=1
                FILE_NEGATIVE_CONTROL_REJECTED=1
                ORACLE_CONTROLS_PASSED=1
                KSU_RESULTS_STABLE=1
                QUERY_METHOD=raw selinuxfs write
                KSU_DOMAIN_VALID=1
                KSU_FILE_VALID=0
                BIT_PAIR=01/10
                FAILURE_REASON=Carrier\ncontext unavailable
                NOTE=Carrier\ncontext: u:r:app_zygote:s0
                NOTE=Query\tmethod\nraw selinuxfs write
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.probeAttempted)
        assertEquals("u:r:app_zygote:s0:c1,c2", snapshot.carrierContext)
        assertTrue(snapshot.carrierMatchesExpected)
        assertTrue(snapshot.carrierControlValid == true)
        assertTrue(snapshot.negativeControlRejected == true)
        assertTrue(snapshot.fileControlValid == true)
        assertTrue(snapshot.fileNegativeControlRejected == true)
        assertTrue(snapshot.oracleControlsPassed)
        assertTrue(snapshot.ksuResultsStable)
        assertEquals("raw selinuxfs write", snapshot.queryMethod)
        assertEquals(true, snapshot.ksuDomainValid)
        assertEquals(false, snapshot.ksuFileValid)
        assertEquals("01/10", snapshot.bitPair)
        assertEquals("Carrier\ncontext unavailable", snapshot.failureReason)
        assertEquals(
            listOf(
                "Carrier\ncontext: u:r:app_zygote:s0",
                "Query\tmethod\nraw selinuxfs write",
            ),
            snapshot.notes,
        )
    }
}
