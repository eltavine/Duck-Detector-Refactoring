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
    fun `support gate failure is unavailable and does not match`() {
        val runtime = FakeRuntime(
            support = ImportKeyRetainedAttestationNarrativeProbe.ImportSupportResult(
                supported = false,
                leafMatchesMarker = false,
                originValue = null,
                originLabel = "unknown",
                detail = "ImportKey support gate failed.",
            ),
        )
        val probe = ImportKeyRetainedAttestationNarrativeProbe(
            runtime = runtime,
            aliasFactory = { "duck_test" },
        )

        val result = probe.inspect()

        assertFalse(result.executed)
        assertFalse(result.importSupported)
        assertFalse(result.retainedNarrativeDetected)
        assertEquals(ImportKeyRetainedAttestationAnomalyKind.IMPORT_UNSUPPORTED, result.anomalyKind)
        assertEquals(listOf("duck_test_support", "duck_test_attack"), runtime.cleanedAliases)
    }

    @Test
    fun `normal imported marker baseline is clean`() {
        val result = ImportKeyRetainedAttestationNarrativeProbe.evaluatePostImportState(
            priorChain = listOf(cert(1), cert(2)),
            snapshots = listOf(
                ImportKeyRetainedAttestationNarrativeProbe.PostImportMetadata(
                    originValue = ORIGIN_IMPORTED,
                    fullChain = listOf(MARKER_CERT),
                    leafMatchesMarker = true,
                ),
            ),
            importedOriginValues = setOf(ORIGIN_IMPORTED),
            generatedOriginValue = ORIGIN_GENERATED,
            originLabel = ::labelOrigin,
        )

        assertTrue(result.executed)
        assertTrue(result.importSupported)
        assertTrue(result.markerImportBaselineClean)
        assertTrue(result.originImported)
        assertTrue(result.postImportLeafMatchesMarker)
        assertFalse(result.retainedNarrativeDetected)
        assertEquals(ImportKeyRetainedAttestationAnomalyKind.NONE, result.anomalyKind)
        assertTrue(result.detail.contains("kind=NONE"))
    }

    @Test
    fun `imported-origin retained prior full-chain is matched`() {
        val prior = listOf(cert(1), cert(2), cert(3))
        val result = ImportKeyRetainedAttestationNarrativeProbe.evaluatePostImportState(
            priorChain = prior,
            snapshots = listOf(
                ImportKeyRetainedAttestationNarrativeProbe.PostImportMetadata(
                    originValue = ORIGIN_IMPORTED,
                    fullChain = listOf(cert(2), cert(3)),
                    leafMatchesMarker = false,
                ),
            ),
            importedOriginValues = setOf(ORIGIN_IMPORTED),
            generatedOriginValue = ORIGIN_GENERATED,
            originLabel = ::labelOrigin,
        )

        assertTrue(result.executed)
        assertTrue(result.retainedNarrativeDetected)
        assertEquals(
            ImportKeyRetainedAttestationAnomalyKind.IMPORTED_RETAINED_PRIOR_CHAIN,
            result.anomalyKind,
        )
        assertEquals(3, result.priorChainLength)
        assertEquals(2, result.postImportChainLength)
        assertEquals(2, result.retainedCertificateCount)
        assertTrue(result.detail.contains("kind=IMPORTED_RETAINED_PRIOR_CHAIN"))
    }

    @Test
    fun `generated-origin stale cached prior chain is matched after support gate`() {
        val prior = listOf(cert(1), cert(2), cert(3))
        val result = ImportKeyRetainedAttestationNarrativeProbe.evaluatePostImportState(
            priorChain = prior,
            snapshots = listOf(
                ImportKeyRetainedAttestationNarrativeProbe.PostImportMetadata(
                    originValue = ORIGIN_GENERATED,
                    fullChain = listOf(cert(1), cert(2), cert(3)),
                    leafMatchesMarker = false,
                ),
            ),
            importedOriginValues = setOf(ORIGIN_IMPORTED),
            generatedOriginValue = ORIGIN_GENERATED,
            originLabel = ::labelOrigin,
        )

        assertTrue(result.executed)
        assertTrue(result.importSupported)
        assertTrue(result.retainedNarrativeDetected)
        assertFalse(result.postImportLeafMatchesMarker)
        assertEquals(
            ImportKeyRetainedAttestationAnomalyKind.STALE_GENERATED_AFTER_IMPORT,
            result.anomalyKind,
        )
        assertEquals(3, result.retainedCertificateCount)
        assertTrue(result.detail.contains("kind=STALE_GENERATED_AFTER_IMPORT"))
    }

    @Test
    fun `first post-import read can be ignored when second read exposes stale generated response`() {
        val runtime = FakeRuntime(
            snapshots = listOf(
                ImportKeyRetainedAttestationNarrativeProbe.PostImportMetadata(
                    originValue = ORIGIN_IMPORTED,
                    fullChain = listOf(MARKER_CERT),
                    leafMatchesMarker = true,
                ),
                ImportKeyRetainedAttestationNarrativeProbe.PostImportMetadata(
                    originValue = ORIGIN_GENERATED,
                    fullChain = listOf(cert(1), cert(2)),
                    leafMatchesMarker = false,
                ),
            ),
        )
        val probe = ImportKeyRetainedAttestationNarrativeProbe(
            runtime = runtime,
            aliasFactory = { "duck_test" },
        )

        val result = probe.inspect()

        assertTrue(result.executed)
        assertTrue(result.retainedNarrativeDetected)
        assertEquals(
            ImportKeyRetainedAttestationAnomalyKind.STALE_GENERATED_AFTER_IMPORT,
            result.anomalyKind,
        )
        assertEquals(listOf("duck_test_support", "duck_test_attack"), runtime.cleanedAliases)
    }

    @Test
    fun `generated-origin without retained overlap is unavailable`() {
        val result = ImportKeyRetainedAttestationNarrativeProbe.evaluatePostImportState(
            priorChain = listOf(cert(1), cert(2)),
            snapshots = listOf(
                ImportKeyRetainedAttestationNarrativeProbe.PostImportMetadata(
                    originValue = ORIGIN_GENERATED,
                    fullChain = listOf(cert(4), cert(5)),
                    leafMatchesMarker = false,
                ),
            ),
            importedOriginValues = setOf(ORIGIN_IMPORTED),
            generatedOriginValue = ORIGIN_GENERATED,
            originLabel = ::labelOrigin,
        )

        assertFalse(result.executed)
        assertFalse(result.retainedNarrativeDetected)
        assertEquals(ImportKeyRetainedAttestationAnomalyKind.UNAVAILABLE, result.anomalyKind)
        assertTrue(result.detail.contains("did not produce"))
    }

    @Test
    fun `runtime import failure is unavailable and cleaned up`() {
        val runtime = FakeRuntime(
            importFailure = IllegalStateException("import failed"),
        )
        val probe = ImportKeyRetainedAttestationNarrativeProbe(
            runtime = runtime,
            aliasFactory = { "duck_test" },
        )

        val result = probe.inspect()

        assertFalse(result.executed)
        assertFalse(result.retainedNarrativeDetected)
        assertEquals(listOf("duck_test_support", "duck_test_attack"), runtime.cleanedAliases)
        assertTrue(result.detail.contains("import failed"))
    }

    private class FakeRuntime(
        private val priorChain: List<ByteArray> = listOf(cert(1), cert(2)),
        private val support: ImportKeyRetainedAttestationNarrativeProbe.ImportSupportResult =
            ImportKeyRetainedAttestationNarrativeProbe.ImportSupportResult(
                supported = true,
                leafMatchesMarker = true,
                originValue = ORIGIN_IMPORTED,
                originLabel = "IMPORTED",
                detail = "origin=IMPORTED, marker import baseline clean.",
            ),
        private val snapshots: List<ImportKeyRetainedAttestationNarrativeProbe.PostImportMetadata> =
            listOf(
                ImportKeyRetainedAttestationNarrativeProbe.PostImportMetadata(
                    originValue = ORIGIN_IMPORTED,
                    fullChain = listOf(MARKER_CERT),
                    leafMatchesMarker = true,
                ),
            ),
        private val importFailure: Throwable? = null,
    ) : ImportKeyRetainedAttestationNarrativeProbe.Runtime {
        val cleanedAliases = mutableListOf<String>()

        override val supported: Boolean = true
        override val importedOriginValues: Set<Int> = setOf(ORIGIN_IMPORTED)
        override val generatedOriginValue: Int = ORIGIN_GENERATED

        override fun generatePriorAttestedChain(alias: String, challenge: ByteArray): List<ByteArray> {
            return priorChain
        }

        override fun importMarkerKey(alias: String) {
            importFailure?.let { throw it }
        }

        override fun verifyImportSupport(alias: String): ImportKeyRetainedAttestationNarrativeProbe.ImportSupportResult {
            importFailure?.let { throw it }
            return support
        }

        override fun readPostImportMetadataSnapshots(alias: String): List<ImportKeyRetainedAttestationNarrativeProbe.PostImportMetadata> {
            return snapshots
        }

        override fun cleanup(alias: String) {
            cleanedAliases += alias
        }

        override fun originLabel(value: Int?): String = labelOrigin(value)
    }

    companion object {
        private const val ORIGIN_GENERATED = 0
        private const val ORIGIN_IMPORTED = 2
        private val MARKER_CERT = cert(99)

        private fun labelOrigin(value: Int?): String {
            return when (value) {
                ORIGIN_GENERATED -> "GENERATED"
                ORIGIN_IMPORTED -> "IMPORTED"
                null -> "unknown"
                else -> value.toString()
            }
        }

        private fun cert(seed: Int): ByteArray {
            return ByteArray(24) { index -> (seed + index).toByte() }
        }
    }
}
