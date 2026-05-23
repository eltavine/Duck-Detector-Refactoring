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

import java.security.UnrecoverableKeyException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GrantDomainFullChainSplitProbeTest {

    @Test
    fun `matching ordered full chains stay clean`() {
        val chain = chain("leaf", "intermediate", "root")

        val comparison = GrantDomainFullChainSplitProbe.compareChains(chain, chain)

        assertFalse(comparison.splitDetected)
        assertEquals(null, comparison.mismatchIndex)
        assertTrue(comparison.detail.contains("matched", ignoreCase = true))
    }

    @Test
    fun `length mismatch detects split`() {
        val comparison = GrantDomainFullChainSplitProbe.compareChains(
            ownerChain = chain("leaf", "intermediate", "root"),
            granteeChain = chain("leaf", "intermediate"),
        )

        assertTrue(comparison.splitDetected)
        assertEquals(2, comparison.mismatchIndex)
        assertTrue(comparison.detail.contains("lengthMismatch"))
    }

    @Test
    fun `leaf mismatch detects split at zero`() {
        val comparison = GrantDomainFullChainSplitProbe.compareChains(
            ownerChain = chain("owner-leaf", "intermediate"),
            granteeChain = chain("grantee-leaf", "intermediate"),
        )

        assertTrue(comparison.splitDetected)
        assertEquals(0, comparison.mismatchIndex)
        assertTrue(comparison.detail.contains("leafMismatch"))
    }

    @Test
    fun `ordered remaining chain mismatch detects split`() {
        val comparison = GrantDomainFullChainSplitProbe.compareChains(
            ownerChain = chain("leaf", "intermediate-a", "root"),
            granteeChain = chain("leaf", "intermediate-b", "root"),
        )

        assertTrue(comparison.splitDetected)
        assertEquals(1, comparison.mismatchIndex)
        assertTrue(comparison.detail.contains("chainMismatch"))
    }

    @Test
    fun `remaining chain ordering mismatch detects split`() {
        val comparison = GrantDomainFullChainSplitProbe.compareChains(
            ownerChain = chain("leaf", "intermediate", "root"),
            granteeChain = chain("leaf", "root", "intermediate"),
        )

        assertTrue(comparison.splitDetected)
        assertEquals(1, comparison.mismatchIndex)
    }

    @Test
    fun `grant alias not found detection requires unrecoverable key exception wording`() {
        assertTrue(
            GrantDomainFullChainSplitProbe.isGrantAliasNotFound(
                UnrecoverableKeyException("No key found by the given alias"),
            ),
        )
        assertFalse(
            GrantDomainFullChainSplitProbe.isGrantAliasNotFound(
                UnrecoverableKeyException("Permission denied"),
            ),
        )
        assertFalse(
            GrantDomainFullChainSplitProbe.isGrantAliasNotFound(
                IllegalStateException("No key found by the given alias"),
            ),
        )
    }

    @Test
    fun `private isolated fallback danger outranks public clean`() {
        val publicResult = GrantDomainFullChainSplitResult(
            executed = true,
            available = true,
            ownerChainLength = 3,
            granteeChainLength = 3,
            anomalyKind = GrantDomainAnomalyKind.NONE,
            detail = "Public: clean",
        )
        val privateResult = GrantDomainFullChainSplitResult(
            executed = true,
            available = true,
            splitDetected = true,
            ownerChainLength = 3,
            granteeChainLength = 2,
            mismatchIndex = 2,
            anomalyKind = GrantDomainAnomalyKind.ISOLATED_CHAIN_SPLIT,
            detail = "Private: matched lengthMismatch owner=3 grantee=2",
        )

        val result = GrantDomainFullChainSplitProbe.selectFinalResult(publicResult, privateResult)

        assertEquals(GrantDomainAnomalyKind.ISOLATED_CHAIN_SPLIT, result.anomalyKind)
        assertTrue(result.detail.contains("Public: Public: clean"))
        assertTrue(result.detail.contains("Private: Private: matched"))
    }

    @Test
    fun `public isolated danger remains final when private is unavailable`() {
        val publicResult = GrantDomainFullChainSplitResult(
            executed = true,
            anomalyKind = GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
            detail = "Public: grant failed",
        )
        val privateResult = GrantDomainFullChainSplitResult(
            detail = "Private: should not execute",
        )

        val result = GrantDomainFullChainSplitProbe.selectFinalResult(publicResult, privateResult)

        assertEquals(GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN, result.anomalyKind)
    }

    private fun chain(vararg labels: String): GrantDomainCertificateChain {
        return GrantDomainCertificateChain(
            labels.map { label ->
                GrantDomainCertificateFingerprint.fromDer(label.toByteArray())
            },
        )
    }
}
