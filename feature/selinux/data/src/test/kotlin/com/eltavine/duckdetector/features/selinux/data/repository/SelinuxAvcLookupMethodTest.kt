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

package com.eltavine.duckdetector.features.selinux.data.repository

import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxAvcLookupChildEnd
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxAvcLookupPayload
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxAvcLookupSnapshot
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxAvcLookupState
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxAvcLookupStep
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAvcLookupCollection
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAvcLookupProfile
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxAvcLookupMethodTest {
    private val collected = SelinuxAvcLookupSnapshot(
        state = SelinuxAvcLookupState.COLLECTED, step = SelinuxAvcLookupStep.FINISHED,
        cpu = 4, cpuRow = 2, cpuRows = 4, possibleCpus = 4, pairs = 128, rounds = 4, writesPerBatch = 4096,
        batchesA = List(4) { 4102L }, batchesB = List(4) { 8198L },
        medianANs = 301, medianBNs = 201, medianDeltaNs = 100, childEnd = SelinuxAvcLookupChildEnd.EXITED,
    )

    @Test fun `collected counts become a typed informational reading`() {
        val result = buildAvcLookupMethod(collected)
        val reading = result.avcLookup!!
        assertEquals(SelinuxOracle.APP_ZYGOTE_AVC_LOOKUPS, result.oracle)
        assertEquals(SelinuxOracle.APP_ZYGOTE_AVC_LOOKUPS.label, result.method)
        assertEquals(SelinuxAvcLookupProfile.ONE_TWO, reading.profile)
        assertEquals(SelinuxAvcLookupProfile.ONE_TWO.label, result.status)
        assertNull(result.isSecure)
        assertFalse(result.permissionDenied)
        assertEquals(listOf(4102L, 4102L, 4102L, 4102L), reading.batchesA)
        assertEquals(2, reading.details.cpuRow)
        assertEquals("FINISHED", reading.details.step)
        assertEquals("EXITED", reading.details.childEnd)
        assertNull(reading.details.unexpectedWrite)
    }

    @Test fun `every collection state keeps its name and failure details`() {
        SelinuxAvcLookupState.entries.forEach { state ->
            val result = buildAvcLookupMethod(SelinuxAvcLookupSnapshot(state = state, failureReason = "reason"))
            assertEquals(state.name, result.avcLookup!!.collection.name)
            assertEquals("reason", result.avcLookup!!.details.failureReason)
            assertEquals(state == SelinuxAvcLookupState.PERMISSION_LIMITED, result.permissionDenied)
            assertNull(result.isSecure)
        }
        val refused = buildAvcLookupMethod(SelinuxAvcLookupSnapshot(
            state = SelinuxAvcLookupState.PERMISSION_LIMITED, step = SelinuxAvcLookupStep.CONTROLS, errno = 13,
            unexpectedPayload = SelinuxAvcLookupPayload.A, unexpectedReturned = -1,
        )).avcLookup!!
        assertEquals(SelinuxAvcLookupCollection.PERMISSION_LIMITED, refused.collection)
        assertEquals("A returned -1", refused.details.unexpectedWrite)
        assertEquals(SelinuxAvcLookupCollection.PERMISSION_LIMITED.label, refused.label)
        assertTrue(refused.details.errno == 13 && refused.details.step == "CONTROLS")
    }
}
