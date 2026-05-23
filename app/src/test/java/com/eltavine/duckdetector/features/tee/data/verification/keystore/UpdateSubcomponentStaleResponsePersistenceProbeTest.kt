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

import java.security.Key
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateSubcomponentStaleResponsePersistenceProbeTest {

    @Test
    fun `support gate failure is unavailable and cleaned up`() {
        val runtime = FakeRuntime(
            support = UpdateSubcomponentStaleResponsePersistenceProbe.CertificateUpdateSupportResult(
                clean = false,
                leafMatchesMarker = false,
                detail = "marker not observable",
            ),
        )
        val probe = UpdateSubcomponentStaleResponsePersistenceProbe(
            runtime = runtime,
            aliasFactory = { "duck_test" },
        )

        val result = probe.inspect()

        assertFalse(result.executed)
        assertFalse(result.supportGateClean)
        assertFalse(result.staleNarrativeDetected)
        assertEquals(
            UpdateSubcomponentStaleResponseAnomalyKind.UPDATE_SUBCOMPONENT_UNOBSERVABLE,
            result.anomalyKind,
        )
        assertEquals(listOf("duck_test_support", "duck_test_attack"), runtime.cleanedAliases)
    }

    @Test
    fun `clean update returns marker leaf without retained prior narrative`() {
        val result = UpdateSubcomponentStaleResponsePersistenceProbe.evaluatePostUpdateState(
            priorChain = listOf(cert(1), cert(2)),
            snapshots = listOf(
                UpdateSubcomponentStaleResponsePersistenceProbe.PostUpdateMetadata(
                    fullChain = listOf(MARKER_CERT),
                    leafMatchesMarker = true,
                ),
            ),
        )

        assertTrue(result.executed)
        assertTrue(result.available)
        assertTrue(result.supportGateClean)
        assertTrue(result.updateSucceeded)
        assertTrue(result.postLeafMatchesMarker)
        assertFalse(result.staleNarrativeDetected)
        assertEquals(UpdateSubcomponentStaleResponseAnomalyKind.NONE, result.anomalyKind)
        assertTrue(result.detail.contains("kind=NONE"))
    }

    @Test
    fun `stale prior full-chain after successful update is matched`() {
        val prior = listOf(cert(1), cert(2), cert(3))
        val result = UpdateSubcomponentStaleResponsePersistenceProbe.evaluatePostUpdateState(
            priorChain = prior,
            snapshots = listOf(
                UpdateSubcomponentStaleResponsePersistenceProbe.PostUpdateMetadata(
                    fullChain = prior,
                    leafMatchesMarker = false,
                ),
            ),
        )

        assertTrue(result.executed)
        assertTrue(result.available)
        assertTrue(result.staleNarrativeDetected)
        assertEquals(
            UpdateSubcomponentStaleResponseAnomalyKind.STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE,
            result.anomalyKind,
        )
        assertEquals(3, result.priorChainLength)
        assertEquals(3, result.postChainLength)
        assertEquals(3, result.retainedCertificateCount)
        assertTrue(result.detail.contains("kind=STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE"))
    }

    @Test
    fun `marker leaf with old intermediate retained is matched`() {
        val prior = listOf(cert(1), cert(2), cert(3))
        val result = UpdateSubcomponentStaleResponsePersistenceProbe.evaluatePostUpdateState(
            priorChain = prior,
            snapshots = listOf(
                UpdateSubcomponentStaleResponsePersistenceProbe.PostUpdateMetadata(
                    fullChain = listOf(MARKER_CERT, cert(2)),
                    leafMatchesMarker = true,
                ),
            ),
        )

        assertTrue(result.staleNarrativeDetected)
        assertTrue(result.postLeafMatchesMarker)
        assertEquals(1, result.retainedCertificateCount)
        assertEquals(
            UpdateSubcomponentStaleResponseAnomalyKind.STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE,
            result.anomalyKind,
        )
    }

    @Test
    fun `final snapshot is used for stable post-update narrative`() {
        val runtime = FakeRuntime(
            snapshots = listOf(
                UpdateSubcomponentStaleResponsePersistenceProbe.PostUpdateMetadata(
                    fullChain = listOf(MARKER_CERT),
                    leafMatchesMarker = true,
                ),
                UpdateSubcomponentStaleResponsePersistenceProbe.PostUpdateMetadata(
                    fullChain = listOf(cert(1), cert(2)),
                    leafMatchesMarker = false,
                ),
            ),
        )
        val probe = UpdateSubcomponentStaleResponsePersistenceProbe(
            runtime = runtime,
            aliasFactory = { "duck_test" },
        )

        val result = probe.inspect()

        assertTrue(result.executed)
        assertTrue(result.staleNarrativeDetected)
        assertEquals(
            UpdateSubcomponentStaleResponseAnomalyKind.STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE,
            result.anomalyKind,
        )
        assertEquals(listOf("duck_test_support", "duck_test_attack"), runtime.cleanedAliases)
    }

    @Test
    fun `update failure is unavailable and does not match stale persistence`() {
        val runtime = FakeRuntime(
            update = UpdateSubcomponentStaleResponsePersistenceProbe.UpdateAttemptResult(
                succeeded = false,
                detail = "setKeyEntry failed: KEY_NOT_FOUND",
            ),
        )
        val probe = UpdateSubcomponentStaleResponsePersistenceProbe(
            runtime = runtime,
            aliasFactory = { "duck_test" },
        )

        val result = probe.inspect()

        assertFalse(result.executed)
        assertFalse(result.staleNarrativeDetected)
        assertEquals(UpdateSubcomponentStaleResponseAnomalyKind.UPDATE_FAILED, result.anomalyKind)
        assertTrue(result.detail.contains("KEY_NOT_FOUND"))
    }

    @Test
    fun `missing post-update metadata is unavailable`() {
        val result = UpdateSubcomponentStaleResponsePersistenceProbe.evaluatePostUpdateState(
            priorChain = listOf(cert(1), cert(2)),
            snapshots = emptyList(),
        )

        assertFalse(result.executed)
        assertFalse(result.staleNarrativeDetected)
        assertEquals(UpdateSubcomponentStaleResponseAnomalyKind.UNAVAILABLE, result.anomalyKind)
        assertTrue(result.detail.contains("no post-update metadata"))
    }

    private class FakeRuntime(
        private val support: UpdateSubcomponentStaleResponsePersistenceProbe.CertificateUpdateSupportResult =
            UpdateSubcomponentStaleResponsePersistenceProbe.CertificateUpdateSupportResult(
                clean = true,
                leafMatchesMarker = true,
                detail = "marker certificate baseline clean.",
            ),
        private val priorChain: List<ByteArray> = listOf(cert(1), cert(2)),
        private val key: Key? = FakeKey,
        private val update: UpdateSubcomponentStaleResponsePersistenceProbe.UpdateAttemptResult =
            UpdateSubcomponentStaleResponsePersistenceProbe.UpdateAttemptResult(
                succeeded = true,
                detail = "setKeyEntry completed.",
            ),
        private val snapshots: List<UpdateSubcomponentStaleResponsePersistenceProbe.PostUpdateMetadata> =
            listOf(
                UpdateSubcomponentStaleResponsePersistenceProbe.PostUpdateMetadata(
                    fullChain = listOf(MARKER_CERT),
                    leafMatchesMarker = true,
                ),
            ),
    ) : UpdateSubcomponentStaleResponsePersistenceProbe.Runtime {
        val cleanedAliases = mutableListOf<String>()

        override fun verifyCertificateUpdateObservability(
            alias: String,
        ): UpdateSubcomponentStaleResponsePersistenceProbe.CertificateUpdateSupportResult = support

        override fun generatePriorAttestedChain(
            alias: String,
            challenge: ByteArray,
            useStrongBox: Boolean,
        ): List<ByteArray> = priorChain

        override fun readExistingKey(alias: String): Key? = key

        override fun updateExistingKeyWithMarker(
            alias: String,
            key: Key,
        ): UpdateSubcomponentStaleResponsePersistenceProbe.UpdateAttemptResult = update

        override fun readPostUpdateMetadataSnapshots(
            alias: String,
        ): List<UpdateSubcomponentStaleResponsePersistenceProbe.PostUpdateMetadata> = snapshots

        override fun cleanup(alias: String) {
            cleanedAliases += alias
        }
    }

    private object FakeKey : Key {
        override fun getAlgorithm(): String = "EC"
        override fun getFormat(): String? = null
        override fun getEncoded(): ByteArray? = null
    }

    companion object {
        private val MARKER_CERT = cert(99)

        private fun cert(seed: Int): ByteArray {
            return ByteArray(24) { index -> (seed + index).toByte() }
        }
    }
}
