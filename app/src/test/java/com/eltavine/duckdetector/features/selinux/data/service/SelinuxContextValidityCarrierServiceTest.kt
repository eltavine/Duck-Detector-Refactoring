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

package com.eltavine.duckdetector.features.selinux.data.service

import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValidityBridge
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValidityPayloadCodec
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValiditySnapshot
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxPolicyloadSeqnoState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxContextValidityCarrierServiceTest {

    @Test
    fun `proc attr current gate does not depend on context oracle controls`() {
        val failureReason = SelinuxContextValidityCarrierService.procAttrCurrentGateFailureReason(
            snapshot = baseSnapshot(
                probeAttempted = true,
                oracleControlsPassed = false,
                ksuResultsStable = false,
                failureReason = "Context validity oracle self-test failed.",
            ),
            appUid = 10000,
            uid = 10000,
        )

        assertNull(failureReason)
    }

    @Test
    fun `proc attr current gate still rejects failed carrier dyntransition self check`() {
        val failureReason = SelinuxContextValidityCarrierService.procAttrCurrentGateFailureReason(
            snapshot = baseSnapshot(
                dyntransitionCheckPassed = false,
            ),
            appUid = 10000,
            uid = 10000,
        )

        assertEquals("Carrier dyntransition self-check failed.", failureReason)
    }

    @Test
    fun `carrier service returns cached preloaded payload without re sampling`() {
        SelinuxContextValidityCarrierService.clearCachedPreloadedPayloadForTests()
        SelinuxContextValidityBridge.clearPreloadedRawDataForTests()
        val expected = SelinuxContextValidityPayloadCodec.encode(
            baseSnapshot().copy(
                probeAttempted = true,
                queryMethod = "raw selinuxfs write",
            ),
        )
        SelinuxContextValidityBridge.setPreloadedRawData(expected)

        val first = SelinuxContextValidityCarrierService.resolveCarrierPayload(
            consumePreloadedRawData = SelinuxContextValidityBridge::consumePreloadedRawDataForCarrier,
        )
        val second = SelinuxContextValidityCarrierService.resolveCarrierPayload(
            consumePreloadedRawData = {
                error("carrier service should not consume preload data twice")
            },
        )

        assertEquals(expected, first)
        assertEquals(expected, second)
    }

    @Test
    fun `carrier service reports unavailable when no preloaded payload exists`() {
        SelinuxContextValidityCarrierService.clearCachedPreloadedPayloadForTests()
        SelinuxContextValidityBridge.clearPreloadedRawDataForTests()

        val payload = SelinuxContextValidityCarrierService.resolveCarrierPayload(
            consumePreloadedRawData = { null },
        )
        val snapshot = SelinuxContextValidityBridge().parse(payload)

        assertFalse(snapshot.available)
        assertEquals("Dedicated app_zygote preload payload unavailable.", snapshot.failureReason)
        assertEquals("Dedicated app_zygote preload payload unavailable.", snapshot.procAttrCurrentFailureReason)
        assertEquals("Dedicated app_zygote preload payload unavailable.", snapshot.dirtyPolicyFailureReason)
        assertEquals("Dedicated app_zygote preload payload unavailable.", snapshot.policyloadSeqnoFailureReason)
        assertEquals(SelinuxPolicyloadSeqnoState.UNAVAILABLE.name, snapshot.policyloadSeqnoState)
        assertTrue(snapshot.policyloadSeqnoNotes.any { it.contains("did not receive a preloaded app_zygote payload") })
        assertTrue(snapshot.notes.any { it.contains("did not receive a preloaded app_zygote payload") })
    }

    private fun baseSnapshot(
        probeAttempted: Boolean = false,
        oracleControlsPassed: Boolean = true,
        ksuResultsStable: Boolean = true,
        dyntransitionCheckPassed: Boolean? = true,
        failureReason: String? = null,
    ): SelinuxContextValiditySnapshot {
        return SelinuxContextValiditySnapshot(
            available = true,
            probeAttempted = probeAttempted,
            carrierContext = "u:r:app_zygote:s0:c1,c2",
            carrierMatchesExpected = true,
            selinuxEnabled = true,
            selinuxEnforced = true,
            pidContextMatchesCurrent = true,
            procSelfContextMatchesCurrent = true,
            dyntransitionCheckPassed = dyntransitionCheckPassed,
            oracleControlsPassed = oracleControlsPassed,
            ksuResultsStable = ksuResultsStable,
            failureReason = failureReason,
        )
    }
}
