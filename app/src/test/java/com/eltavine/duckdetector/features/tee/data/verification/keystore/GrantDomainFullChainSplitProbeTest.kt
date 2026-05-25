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
    fun `private isolated crash matcher requires the full keystore service stack signature`() {
        assertTrue(
            GrantDomainFullChainSplitProbe.matchesPrivateIsolatedCrashSignature(
                """
                java.lang.reflect.InvocationTargetException
                Caused by: android.os.ServiceSpecificException: system/security/keystore2/src/service.rs:157: while trying to load key info.

                Caused by:
                    0: No legacy keys for key descriptor.
                    1: Error::Rc(r#KEY_NOT_FOUND) (code 7)
                """.trimIndent(),
            ),
        )
        assertFalse(
            GrantDomainFullChainSplitProbe.matchesPrivateIsolatedCrashSignature(
                "ServiceSpecificException(code 7): partial stack only",
            ),
        )
    }

    @Test
    fun `private isolated danger outranks clean Java stages`() {
        val publicResult = GrantDomainFullChainSplitResult(
            executed = true,
            available = true,
            anomalyKind = GrantDomainAnomalyKind.NONE,
            detail = "Public: clean",
        )
        val hiddenResult = GrantDomainFullChainSplitResult(
            executed = true,
            available = true,
            anomalyKind = GrantDomainAnomalyKind.NONE,
            detail = "Hidden: clean",
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

        val result = GrantDomainFullChainSplitProbe.selectFinalResult(
            publicResult,
            hiddenResult,
            privateResult,
        )

        assertEquals(GrantDomainAnomalyKind.ISOLATED_CHAIN_SPLIT, result.anomalyKind)
        assertTrue(result.detail.contains("Public: clean"))
        assertTrue(result.detail.contains("Hidden: clean"))
        assertTrue(result.detail.contains("Private: matched"))
    }

    @Test
    fun `private isolated clean is selected after unsupported Java stages`() {
        val publicResult = GrantDomainFullChainSplitResult(
            anomalyKind = GrantDomainAnomalyKind.UNAVAILABLE,
            detail = "Public: unsupported",
        )
        val hiddenResult = GrantDomainFullChainSplitResult(
            anomalyKind = GrantDomainAnomalyKind.UNAVAILABLE,
            detail = "Hidden: unavailable",
        )
        val privateResult = GrantDomainFullChainSplitResult(
            executed = true,
            available = true,
            anomalyKind = GrantDomainAnomalyKind.NONE,
            detail = "Private: clean",
        )

        val result = GrantDomainFullChainSplitProbe.selectFinalResult(
            publicResult,
            hiddenResult,
            privateResult,
        )

        assertEquals(GrantDomainAnomalyKind.NONE, result.anomalyKind)
        assertTrue(result.detail.contains("Public: unsupported"))
        assertTrue(result.detail.contains("Hidden: unavailable"))
        assertTrue(result.detail.contains("Private: clean"))
    }

    @Test
    fun `private isolated readback blocked stays unavailable`() {
        val publicResult = GrantDomainFullChainSplitResult(
            executed = true,
            available = true,
            anomalyKind = GrantDomainAnomalyKind.NONE,
            detail = "Public: clean",
        )
        val hiddenResult = GrantDomainFullChainSplitResult(
            executed = true,
            available = true,
            anomalyKind = GrantDomainAnomalyKind.NONE,
            detail = "Hidden: clean",
        )
        val privateResult = GrantDomainFullChainSplitResult(
            ownerChainLength = 3,
            anomalyKind = GrantDomainAnomalyKind.UNAVAILABLE,
            detail = "Private: readback failed (isolated binder call blocked: permission denied).",
        )

        val result = GrantDomainFullChainSplitProbe.selectFinalResult(
            publicResult,
            hiddenResult,
            privateResult,
        )

        assertEquals(GrantDomainAnomalyKind.NONE, result.anomalyKind)
        assertTrue(result.detail.contains("Private: readback failed"))
    }

    @Test
    fun `hidden isolated fallback danger outranks public unavailable and private skip`() {
        val publicResult = GrantDomainFullChainSplitResult(
            anomalyKind = GrantDomainAnomalyKind.NONE,
            detail = "Public: unsupported",
        )
        val hiddenResult = GrantDomainFullChainSplitResult(
            executed = true,
            available = true,
            splitDetected = true,
            ownerChainLength = 3,
            granteeChainLength = 2,
            mismatchIndex = 2,
            anomalyKind = GrantDomainAnomalyKind.ISOLATED_CHAIN_SPLIT,
            detail = "Hidden: matched lengthMismatch owner=3 grantee=2",
        )
        val privateResult = GrantDomainFullChainSplitResult(
            detail = "skipped because Java grant stage already detected danger",
        )

        val result = GrantDomainFullChainSplitProbe.selectFinalResult(
            publicResult,
            hiddenResult,
            privateResult,
        )

        assertEquals(GrantDomainAnomalyKind.ISOLATED_CHAIN_SPLIT, result.anomalyKind)
        assertTrue(result.detail.contains("Public: unsupported"))
        assertTrue(result.detail.contains("Hidden: matched"))
        assertTrue(result.detail.contains("Private: skipped"))
    }

    @Test
    fun `private isolated crash outranks clean Java stages`() {
        val publicResult = GrantDomainFullChainSplitResult(
            executed = true,
            available = true,
            anomalyKind = GrantDomainAnomalyKind.NONE,
            detail = "Public: clean",
        )
        val hiddenResult = GrantDomainFullChainSplitResult(
            executed = true,
            available = true,
            anomalyKind = GrantDomainAnomalyKind.NONE,
            detail = "Hidden: clean",
        )
        val privateResult = GrantDomainFullChainSplitResult(
            executed = true,
            available = false,
            ownerChainLength = 3,
            granteeUid = 99001,
            anomalyKind = GrantDomainAnomalyKind.ISOLATED_PRIVATE_READBACK_CRASH,
            detail = "Private: isolated readback crashed after grant succeeded.",
            diagnosticCopyText = """
                java.lang.reflect.InvocationTargetException
                Caused by: android.os.ServiceSpecificException: system/security/keystore2/src/service.rs:157: while trying to load key info.

                Caused by:
                    0: No legacy keys for key descriptor.
                    1: Error::Rc(r#KEY_NOT_FOUND) (code 7)
            """.trimIndent(),
        )

        val result = GrantDomainFullChainSplitProbe.selectFinalResult(
            publicResult,
            hiddenResult,
            privateResult,
        )

        assertEquals(GrantDomainAnomalyKind.ISOLATED_PRIVATE_READBACK_CRASH, result.anomalyKind)
        assertTrue(result.detail.contains("Public: clean"))
        assertTrue(result.detail.contains("Hidden: clean"))
        assertTrue(result.detail.contains("Private: isolated readback crashed"))
    }

    @Test
    fun `public isolated danger remains final when hidden is unavailable`() {
        val publicResult = GrantDomainFullChainSplitResult(
            executed = true,
            anomalyKind = GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
            detail = "Public: grant failed",
        )
        val hiddenResult = GrantDomainFullChainSplitResult(
            detail = "Hidden: should not execute",
        )
        val privateResult = GrantDomainFullChainSplitResult(
            detail = "Private: should not execute",
        )

        val result = GrantDomainFullChainSplitProbe.selectFinalResult(
            publicResult,
            hiddenResult,
            privateResult,
        )

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
