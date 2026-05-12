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

package com.eltavine.duckdetector.features.lsposed.data.probes

import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodOutcome
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValiditySnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LSPosedDirtyPolicyProbeTest {

    private val probe = LSPosedDirtyPolicyProbe()

    @Test
    fun `lsposed file rule becomes policy danger signal`() {
        val result = probe.run(
            SelinuxContextValiditySnapshot(
                dirtyPolicyAvailable = true,
                dirtyPolicyProbeAttempted = true,
                dirtyPolicyCarrierContext = "u:r:app_zygote:s0:c1,c2",
                dirtyPolicyCarrierMatchesExpected = true,
                dirtyPolicyControlsPassed = true,
                dirtyPolicyStable = true,
                dirtyPolicyQueryMethod = "android.os.SELinux.checkSELinuxAccess",
                dirtyPolicyAccessControlAllowed = true,
                dirtyPolicyNegativeControlRejected = true,
                dirtyPolicyLsposedFileReadAllowed = true,
            ),
        )

        assertTrue(result.available)
        assertEquals("LSPosed rule present", result.summary)
        assertEquals(LSPosedMethodOutcome.DETECTED, result.outcome)
        assertEquals(1, result.hitCount)
        assertTrue(
            result.signals.any {
                it.group == LSPosedSignalGroup.POLICY &&
                    it.label == "LSPosed file read" &&
                    it.value == "Allowed"
            },
        )
    }

    @Test
    fun `supporting root policy rule stays review level for LSPosed card`() {
        val result = probe.run(
            SelinuxContextValiditySnapshot(
                dirtyPolicyAvailable = true,
                dirtyPolicyProbeAttempted = true,
                dirtyPolicyCarrierContext = "u:r:app_zygote:s0:c1,c2",
                dirtyPolicyCarrierMatchesExpected = true,
                dirtyPolicyControlsPassed = true,
                dirtyPolicyStable = true,
                dirtyPolicyQueryMethod = "android.os.SELinux.checkSELinuxAccess",
                dirtyPolicyAccessControlAllowed = true,
                dirtyPolicyNegativeControlRejected = true,
                dirtyPolicyMagiskBinderCallAllowed = true,
                dirtyPolicyKsuFileReadAllowed = false,
                dirtyPolicyLsposedFileReadAllowed = false,
            ),
        )

        assertTrue(result.available)
        assertEquals("1 dirty rule(s)", result.summary)
        assertEquals(LSPosedMethodOutcome.WARNING, result.outcome)
        assertEquals(1, result.hitCount)
        assertTrue(
            result.signals.any {
                it.group == LSPosedSignalGroup.POLICY &&
                    it.label == "Magisk binder" &&
                    it.severity == LSPosedSignalSeverity.WARNING
            },
        )
    }

    @Test
    fun `lsposed file rule stays visible when the oracle self test is imperfect`() {
        val result = probe.run(
            SelinuxContextValiditySnapshot(
                dirtyPolicyAvailable = true,
                dirtyPolicyProbeAttempted = true,
                dirtyPolicyCarrierContext = "u:r:app_zygote:s0:c1,c2",
                dirtyPolicyCarrierMatchesExpected = true,
                dirtyPolicyControlsPassed = false,
                dirtyPolicyStable = false,
                dirtyPolicyQueryMethod = "android.os.SELinux.checkSELinuxAccess",
                dirtyPolicyAccessControlAllowed = false,
                dirtyPolicyNegativeControlRejected = false,
                dirtyPolicyLsposedFileReadAllowed = true,
                dirtyPolicyFailureReason = "Dirty policy oracle self-test failed.",
            ),
        )

        assertFalse(result.available)
        assertEquals("Unavailable", result.summary)
        assertEquals(LSPosedMethodOutcome.SUPPORT, result.outcome)
        assertEquals(0, result.hitCount)
        assertTrue(result.signals.isEmpty())
        assertTrue(result.detail.contains("controls=failed"))
    }

    @Test
    fun `untrusted dirty policy carrier does not create signals`() {
        val result = probe.run(
            SelinuxContextValiditySnapshot(
                dirtyPolicyAvailable = true,
                dirtyPolicyProbeAttempted = true,
                dirtyPolicyCarrierContext = "u:r:untrusted_app:s0:c1,c2",
                dirtyPolicyCarrierMatchesExpected = false,
                dirtyPolicyControlsPassed = false,
                dirtyPolicyStable = false,
                dirtyPolicyLsposedFileReadAllowed = true,
                dirtyPolicyFailureReason = "Carrier context is not app_zygote.",
            ),
        )

        assertFalse(result.available)
        assertEquals(LSPosedMethodOutcome.SUPPORT, result.outcome)
        assertEquals("Unavailable", result.summary)
        assertTrue(result.signals.isEmpty())
    }
}
