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

package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValidityBridge
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValiditySnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxContextValidityProbeTest {

    @Test
    fun `clean snapshot maps to strong clean state`() {
        val result = SelinuxContextValidityProbe(
            nativeBridge = FakeSelinuxContextValidityBridge(
                SelinuxContextValiditySnapshot(
                    available = true,
                    probeAttempted = true,
                    carrierContext = "u:r:app_zygote:s0:c1,c2",
                    carrierMatchesExpected = true,
                    selinuxEnabled = true,
                    selinuxEnforced = true,
                    pidContextMatchesCurrent = true,
                    procSelfContextMatchesCurrent = true,
                    dyntransitionCheckPassed = true,
                    carrierControlValid = true,
                    negativeControlRejected = true,
                    fileControlValid = true,
                    fileNegativeControlRejected = true,
                    oracleControlsPassed = true,
                    ksuResultsStable = true,
                    queryMethod = "raw selinuxfs write",
                    ksuDomainValid = false,
                    ksuFileValid = false,
                    bitPair = SelinuxContextValidityProbe.BITPAIR_CLEAN,
                    procAttrCurrentProbeAttempted = true,
                    procAttrCurrentResults = listOf(
                        SelinuxProcAttrCurrentResult(
                            label = "KernelSU",
                            targetContext = "u:r:ksu:s0",
                            outcomeClass = SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL,
                            rawMessage = "ErrnoException: errno=22, Invalid argument",
                        ),
                    ),
                    notes = listOf("Carrier context: u:r:app_zygote:s0:c1,c2"),
                ),
            ),
        ).inspect()

        assertEquals(SelinuxContextValidityState.CLEAN, result.state)
        assertEquals(SelinuxContextValidityProbe.BITPAIR_CLEAN, result.bitPair)
        assertEquals(true, result.selinuxEnabled)
        assertEquals(true, result.selinuxEnforced)
        assertEquals(true, result.procAttrCurrentProbeAttempted)
        assertEquals(1, result.procAttrCurrentResults.size)
        assertTrue(result.notes.any { it.contains("Bit pair 00") })
    }

    @Test
    fun `ksu snapshot maps to strong ksu state`() {
        val result = SelinuxContextValidityProbe(
            nativeBridge = FakeSelinuxContextValidityBridge(
                SelinuxContextValiditySnapshot(
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
                    ksuFileValid = true,
                    bitPair = SelinuxContextValidityProbe.BITPAIR_KSU_PRESENT,
                    notes = listOf("Carrier context: u:r:app_zygote:s0:c1,c2"),
                ),
            ),
        ).inspect()

        assertEquals(SelinuxContextValidityState.KSU_PRESENT, result.state)
        assertEquals(SelinuxContextValidityProbe.BITPAIR_KSU_PRESENT, result.bitPair)
        assertTrue(result.notes.any { it.contains("Bit pair 11") })
    }

    @Test
    fun `failed oracle controls are not interpreted as ksu or clean`() {
        val result = SelinuxContextValidityProbe(
            nativeBridge = FakeSelinuxContextValidityBridge(
                SelinuxContextValiditySnapshot(
                    available = true,
                    probeAttempted = true,
                    carrierContext = "u:r:app_zygote:s0:c1,c2",
                    carrierMatchesExpected = true,
                    carrierControlValid = true,
                    negativeControlRejected = false,
                    fileControlValid = true,
                    fileNegativeControlRejected = false,
                    oracleControlsPassed = false,
                    ksuResultsStable = false,
                    queryMethod = "raw selinuxfs write",
                    failureReason = "Context validity oracle self-test failed.",
                    notes = listOf("Negative control accepted"),
                ),
            ),
        ).inspect()

        assertEquals(SelinuxContextValidityState.INCONSISTENT, result.state)
        assertTrue(result.notes.any { it.contains("not trusted") })
    }

    @Test
    fun `repeatability failure is not interpreted as clean or ksu`() {
        val result = SelinuxContextValidityProbe(
            nativeBridge = FakeSelinuxContextValidityBridge(
                SelinuxContextValiditySnapshot(
                    available = true,
                    probeAttempted = true,
                    carrierContext = "u:r:app_zygote:s0:c1,c2",
                    carrierMatchesExpected = true,
                    carrierControlValid = true,
                    negativeControlRejected = true,
                    fileControlValid = true,
                    fileNegativeControlRejected = true,
                    oracleControlsPassed = true,
                    ksuResultsStable = false,
                    queryMethod = "raw selinuxfs write",
                    failureReason = "Context validity oracle repeatability failed.",
                    notes = listOf("The KSU-specific context verdict changed across repeated writes, so it was not trusted."),
                ),
            ),
        ).inspect()

        assertEquals(SelinuxContextValidityState.INCONSISTENT, result.state)
        assertTrue(result.failureReason?.contains("repeatability failed") == true)
        assertTrue(result.notes.any { it.contains("not trusted") })
    }

    @Test
    fun `non app zygote carrier stays unavailable`() {
        val result = SelinuxContextValidityProbe(
            nativeBridge = FakeSelinuxContextValidityBridge(
                SelinuxContextValiditySnapshot(
                    available = true,
                    probeAttempted = false,
                    carrierContext = "u:r:untrusted_app:s0:c1,c2",
                    carrierMatchesExpected = false,
                    failureReason = "Carrier context is not app_zygote.",
                    notes = listOf("The oracle is only meaningful from an app_zygote carrier."),
                ),
            ),
        ).inspect()

        assertEquals(SelinuxContextValidityState.UNAVAILABLE, result.state)
        assertTrue(result.failureReason?.contains("app_zygote") == true)
    }

    @Test
    fun `app zygote like prefix does not pass carrier gate`() {
        val result = SelinuxContextValidityProbe(
            nativeBridge = FakeSelinuxContextValidityBridge(
                SelinuxContextValiditySnapshot(
                    available = true,
                    probeAttempted = false,
                    carrierContext = "u:r:app_zygote_helper:s0",
                    carrierMatchesExpected = false,
                    failureReason = "Carrier context is not app_zygote.",
                    notes = listOf("The oracle is only meaningful from an app_zygote carrier."),
                ),
            ),
        ).inspect()

        assertEquals(SelinuxContextValidityState.UNAVAILABLE, result.state)
        assertTrue(result.failureReason?.contains("app_zygote") == true)
    }

    private class FakeSelinuxContextValidityBridge(
        private val snapshot: SelinuxContextValiditySnapshot,
    ) : SelinuxContextValidityBridge() {
        override fun collectSnapshot(): SelinuxContextValiditySnapshot = snapshot
    }
}
