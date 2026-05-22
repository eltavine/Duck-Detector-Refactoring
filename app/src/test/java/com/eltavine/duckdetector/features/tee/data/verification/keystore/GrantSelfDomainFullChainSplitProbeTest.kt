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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GrantSelfDomainFullChainSplitProbeTest {

    @Test
    fun `matching owner and self grant chains stay clean`() {
        val chain = chain("leaf", "intermediate", "root")

        val comparison = GrantSelfDomainFullChainSplitProbe.compareChains(chain, chain)

        assertFalse(comparison.splitDetected)
        assertEquals(null, comparison.mismatchIndex)
    }

    @Test
    fun `leaf mismatch detects self grant split`() {
        val comparison = GrantSelfDomainFullChainSplitProbe.compareChains(
            ownerChain = chain("owner-leaf", "intermediate"),
            grantChain = chain("grant-leaf", "intermediate"),
        )

        assertTrue(comparison.splitDetected)
        assertEquals(0, comparison.mismatchIndex)
        assertTrue(comparison.detail.contains("leafMismatch"))
    }

    @Test
    fun `ordered chain mismatch detects self grant split`() {
        val comparison = GrantSelfDomainFullChainSplitProbe.compareChains(
            ownerChain = chain("leaf", "intermediate", "root"),
            grantChain = chain("leaf", "root", "intermediate"),
        )

        assertTrue(comparison.splitDetected)
        assertEquals(1, comparison.mismatchIndex)
    }

    @Test
    fun `length mismatch detects self grant split`() {
        val comparison = GrantSelfDomainFullChainSplitProbe.compareChains(
            ownerChain = chain("leaf", "intermediate", "root"),
            grantChain = chain("leaf", "intermediate"),
        )

        assertTrue(comparison.splitDetected)
        assertEquals(2, comparison.mismatchIndex)
    }

    private fun chain(vararg labels: String): GrantDomainCertificateChain {
        return GrantDomainCertificateChain(
            labels.map { label ->
                GrantDomainCertificateFingerprint.fromDer(label.toByteArray())
            },
        )
    }
}
