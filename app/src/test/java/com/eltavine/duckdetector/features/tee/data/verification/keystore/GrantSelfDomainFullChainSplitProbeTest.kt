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

    @Test
    fun `private fallback danger outranks public clean`() {
        val publicResult = GrantSelfDomainFullChainSplitResult(
            executed = true,
            available = true,
            ownerChainLength = 3,
            grantChainLength = 3,
            anomalyKind = GrantSelfDomainAnomalyKind.NONE,
            detail = "Public: clean",
        )
        val privateResult = GrantSelfDomainFullChainSplitResult(
            executed = true,
            available = true,
            splitDetected = true,
            ownerChainLength = 3,
            grantChainLength = 2,
            mismatchIndex = 2,
            anomalyKind = GrantSelfDomainAnomalyKind.SELF_CHAIN_SPLIT,
            detail = "Private: matched lengthMismatch owner=3 grantee=2",
        )

        val result = GrantSelfDomainFullChainSplitProbe.selectFinalResult(publicResult, privateResult)

        assertEquals(GrantSelfDomainAnomalyKind.SELF_CHAIN_SPLIT, result.anomalyKind)
        assertTrue(result.detail.contains("Public: Public: clean"))
        assertTrue(result.detail.contains("Private: Private: matched"))
    }

    @Test
    fun `public danger suppresses private fallback selection`() {
        val publicResult = GrantSelfDomainFullChainSplitResult(
            executed = true,
            anomalyKind = GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
            detail = "Public: grant failed",
        )
        val privateResult = GrantSelfDomainFullChainSplitResult(
            detail = "Private: should not execute",
        )

        val result = GrantSelfDomainFullChainSplitProbe.selectFinalResult(publicResult, privateResult)

        assertEquals(GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN, result.anomalyKind)
    }

    private fun chain(vararg labels: String): GrantDomainCertificateChain {
        return GrantDomainCertificateChain(
            labels.map { label ->
                GrantDomainCertificateFingerprint.fromDer(label.toByteArray())
            },
        )
    }
}
