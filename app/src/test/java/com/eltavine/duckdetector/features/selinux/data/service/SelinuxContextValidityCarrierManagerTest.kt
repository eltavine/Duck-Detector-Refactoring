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

import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxPolicyloadSeqnoState
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test

class SelinuxContextValidityCarrierManagerTest {

    @Test
    fun `missing context reports carrier failure across related probes`() = runBlocking {
        val snapshot = SelinuxContextValidityCarrierManager(context = null).collectSnapshot()

        assertEquals("SELinux carrier service unavailable.", snapshot.failureReason)
        assertEquals("SELinux carrier service unavailable.", snapshot.procAttrCurrentFailureReason)
        assertEquals("SELinux carrier service unavailable.", snapshot.dirtyPolicyFailureReason)
        assertEquals("SELinux carrier service unavailable.", snapshot.policyloadSeqnoFailureReason)
        assertEquals(SelinuxPolicyloadSeqnoState.UNAVAILABLE.name, snapshot.policyloadSeqnoState)
    }
}
