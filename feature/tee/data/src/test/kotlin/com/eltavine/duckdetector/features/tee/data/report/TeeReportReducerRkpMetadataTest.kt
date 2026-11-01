package com.eltavine.duckdetector.features.tee.data.report

import com.eltavine.duckdetector.features.tee.domain.TeeRkpState
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TeeReportReducerRkpMetadataTest {
    private val reducer = TeeReportReducer()

    @Test
    fun `approval text does not affect verdict score or indicator counts`() {
        val base = TeeRkpState(provisioned = true, serverSigned = true)
        val baseline = reducer.reduce(baseArtifacts(rkp = base))
        for (status in listOf("APPROVED", "NOT_APPROVED", "UNKNOWN_FUTURE_VALUE")) {
            val report = reducer.reduce(baseArtifacts(rkp = base.copy(buildMetadata = "{1: \"$status\"}")))
            assertEquals(baseline.verdict, report.verdict)
            assertEquals(baseline.tamperScore, report.tamperScore)
            assertEquals(baseline.supplementaryIndicatorCount, report.supplementaryIndicatorCount)
            assertEquals(baseline.localTrustChainLevel, report.localTrustChainLevel)
            val row = report.sections.flatMap { it.items }.single { it.title == "RKP build metadata" }
            assertEquals(TeeSignalLevel.INFO, row.level)
            assertTrue(row.body.contains(status))
            assertTrue(row.body.contains("CTS status cannot be determined"))
            assertTrue(row.body.contains("RKP V3"))
            assertTrue(row.body.contains("Fingerprint and VBMeta were not compared"))
            assertTrue(row.body.contains("may predate a system update"))
            assertTrue(report.exportText.contains(row.body))
        }
    }

    @Test
    fun `CSR style field names in certificate metadata do not establish current build consistency`() {
        val base = TeeRkpState(provisioned = true, serverSigned = true)
        val baseline = reducer.reduce(baseArtifacts(rkp = base))
        for (metadata in listOf(
            "{\"fingerprint\": \"brand/product/device:16/old/1:user/release-keys\"}",
            "{\"vbmeta_digest\": h'FFEE'}",
            "{1: \"brand/product/device:16/new/2:user/release-keys\", 4: h'AABB'}",
        )) {
            val report = reducer.reduce(baseArtifacts(rkp = base.copy(buildMetadata = metadata)))
            val row = report.sections.flatMap { it.items }.single { it.title == "RKP build metadata" }

            assertEquals(TeeSignalLevel.INFO, row.level)
            assertEquals(baseline.verdict, report.verdict)
            assertEquals(baseline.tamperScore, report.tamperScore)
            assertEquals(baseline.supplementaryIndicatorCount, report.supplementaryIndicatorCount)
            assertTrue(row.body.contains(metadata))
            assertTrue(row.body.contains("certificate field mapping is undocumented"))
            assertTrue(report.exportText.contains(row.body))
        }
    }

    @Test
    fun `absent and malformed metadata remain distinguishable and informational`() {
        val base = TeeRkpState(provisioned = true, serverSigned = true)
        val absent = reducer.reduce(baseArtifacts(rkp = base))
        val malformed = reducer.reduce(baseArtifacts(rkp = base.copy(provisioningInfoIssue = "Invalid CBOR.")))
        val absentRow = absent.sections.flatMap { it.items }.single { it.title == "RKP build metadata" }
        val malformedRow = malformed.sections.flatMap { it.items }.single { it.title == "RKP build metadata" }
        assertTrue(absentRow.body.contains("not included"))
        assertTrue(malformedRow.body.contains("not fully decoded"))
        assertTrue(malformedRow.body.contains("Invalid CBOR"))
        assertEquals(TeeSignalLevel.INFO, malformedRow.level)
        assertEquals(absent.verdict, malformed.verdict)
        assertEquals(absent.tamperScore, malformed.tamperScore)
    }

    @Test
    fun `unauthenticated metadata is withheld even if a caller supplies values`() {
        val report = reducer.reduce(baseArtifacts(rkp = TeeRkpState(
            provisioned = true,
            serverSigned = false,
            buildMetadata = "untrusted-metadata",
        )))
        val row = report.sections.flatMap { it.items }.single { it.title == "RKP build metadata" }
        assertTrue(row.body.contains("not authenticated"))
        assertTrue(!row.body.contains("untrusted-metadata"))
    }
}
