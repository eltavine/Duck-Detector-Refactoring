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

class ImportKeyRetainedAttestationNarrativeProbeTest {

    @Test
    fun `retained prior chain in imported-origin response is matched`() {
        val prior = listOf(cert(1), cert(2), cert(3))
        val result = ImportKeyRetainedAttestationNarrativeProbe.evaluatePostImportState(
            priorChain = prior,
            postImportChain = listOf(cert(2), cert(3)),
            originValue = ORIGIN_IMPORTED,
            importedOriginValues = setOf(ORIGIN_IMPORTED),
            originLabel = "IMPORTED",
        )

        assertTrue(result.executed)
        assertTrue(result.originImported)
        assertTrue(result.retainedNarrativeDetected)
        assertEquals(3, result.priorChainLength)
        assertEquals(2, result.postImportChainLength)
        assertEquals(2, result.retainedCertificateCount)
        assertTrue(result.detail.contains("firstRetained"))
    }

    @Test
    fun `imported-origin response without certificate chain is clean`() {
        val result = ImportKeyRetainedAttestationNarrativeProbe.evaluatePostImportState(
            priorChain = listOf(cert(1), cert(2)),
            postImportChain = emptyList(),
            originValue = ORIGIN_IMPORTED,
            importedOriginValues = setOf(ORIGIN_IMPORTED),
            originLabel = "IMPORTED",
        )

        assertTrue(result.executed)
        assertTrue(result.originImported)
        assertFalse(result.retainedNarrativeDetected)
        assertEquals(0, result.postImportChainLength)
        assertTrue(result.detail.contains("no certificateChain"))
    }

    @Test
    fun `missing origin is unavailable and does not match`() {
        val result = ImportKeyRetainedAttestationNarrativeProbe.evaluatePostImportState(
            priorChain = listOf(cert(1)),
            postImportChain = listOf(cert(1)),
            originValue = null,
            importedOriginValues = setOf(ORIGIN_IMPORTED),
        )

        assertFalse(result.executed)
        assertFalse(result.originImported)
        assertFalse(result.retainedNarrativeDetected)
        assertTrue(result.detail.contains("ORIGIN"))
    }

    @Test
    fun `non-matching post-import chain is unavailable and does not match`() {
        val result = ImportKeyRetainedAttestationNarrativeProbe.evaluatePostImportState(
            priorChain = listOf(cert(1), cert(2)),
            postImportChain = listOf(cert(4), cert(5)),
            originValue = ORIGIN_IMPORTED,
            importedOriginValues = setOf(ORIGIN_IMPORTED),
            originLabel = "IMPORTED",
        )

        assertFalse(result.executed)
        assertFalse(result.retainedNarrativeDetected)
        assertTrue(result.detail.contains("did not match"))
    }

    @Test
    fun `runtime import failure is unavailable and cleaned up`() {
        val runtime = FakeRuntime(
            importFailure = IllegalStateException("import failed"),
        )
        val probe = ImportKeyRetainedAttestationNarrativeProbe(
            runtime = runtime,
            aliasFactory = { "duck_test_alias" },
        )

        val result = probe.inspect()

        assertFalse(result.executed)
        assertFalse(result.retainedNarrativeDetected)
        assertEquals(listOf("duck_test_alias"), runtime.cleanedAliases)
        assertTrue(result.detail.contains("import failed"))
    }

    @Test
    fun `runtime binder metadata unavailable does not escape scan`() {
        val runtime = FakeRuntime(metadata = null)
        val probe = ImportKeyRetainedAttestationNarrativeProbe(
            runtime = runtime,
            aliasFactory = { "duck_test_alias" },
        )

        val result = probe.inspect()

        assertFalse(result.executed)
        assertFalse(result.retainedNarrativeDetected)
        assertEquals(listOf("duck_test_alias"), runtime.cleanedAliases)
        assertTrue(result.detail.contains("metadata"))
    }

    private class FakeRuntime(
        private val priorChain: List<ByteArray> = listOf(cert(1), cert(2)),
        private val metadata: ImportKeyRetainedAttestationNarrativeProbe.PostImportMetadata? =
            ImportKeyRetainedAttestationNarrativeProbe.PostImportMetadata(
                originValue = ORIGIN_IMPORTED,
                certificateChain = listOf(cert(2)),
            ),
        private val importFailure: Throwable? = null,
    ) : ImportKeyRetainedAttestationNarrativeProbe.Runtime {
        val cleanedAliases = mutableListOf<String>()

        override val supported: Boolean = true
        override val importedOriginValues: Set<Int> = setOf(ORIGIN_IMPORTED)

        override fun generatePriorAttestedChain(alias: String, challenge: ByteArray): List<ByteArray> {
            return priorChain
        }

        override fun importMarkerKey(alias: String) {
            importFailure?.let { throw it }
        }

        override fun readPostImportMetadata(alias: String): ImportKeyRetainedAttestationNarrativeProbe.PostImportMetadata? {
            return metadata
        }

        override fun cleanup(alias: String) {
            cleanedAliases += alias
        }
    }

    companion object {
        private const val ORIGIN_IMPORTED = 2

        private fun cert(seed: Int): ByteArray {
            return ByteArray(24) { index -> (seed + index).toByte() }
        }
    }
}
