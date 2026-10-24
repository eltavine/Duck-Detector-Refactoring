package com.eltavine.duckdetector.features.selinux.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import org.junit.Assert.assertEquals
import org.junit.Test

class SelinuxDirtySepolicyRawStatusTest {
    @Test
    fun `App Zygote startup or connection failure is warning without any raw policy result`() {
        val report = report(null).copy(methods = listOf(SelinuxCheckResult(
            method = SelinuxOracle.CONTEXT_VALIDITY.label,
            status = SelinuxContextValidityVerdict.UNSUPPORTED.label,
            isSecure = null,
            permissionDenied = false,
            oracle = SelinuxOracle.CONTEXT_VALIDITY,
            contextValidity = SelinuxContextValidityReading(
                SelinuxContextValidityVerdict.UNSUPPORTED,
                AppZygoteCarrierSupportState.FAILED,
            ),
        )))
        assertEquals(DetectorStatus.warning(), report.toDetectorStatus())
        assertEquals(DetectorStatus.warning(), report.copy(mode = SelinuxMode.UNKNOWN).toDetectorStatus())
    }

    @Test
    fun `failed standalone access oracle without failed carrier remains unavailable not warning`() {
        assertEquals(DetectorStatus.allClear(), report(null).toDetectorStatus())
    }

    @Test
    fun `strong DirtySepolicy anomalies are danger for enforcing and unknown modes`() {
        assertEquals(DetectorStatus.danger(), report(false, danger = true).toDetectorStatus())
        assertEquals(DetectorStatus.danger(), report(false, danger = true).copy(mode = SelinuxMode.UNKNOWN).toDetectorStatus())
    }

    @Test
    fun `ordinary Raw evidence still remains warning without strong anomaly`() {
        assertEquals(DetectorStatus.warning(), report(false).toDetectorStatus())
        assertEquals(DetectorStatus.warning(), report(false).copy(mode = SelinuxMode.UNKNOWN).toDetectorStatus())
    }

    @Test
    fun `unavailable raw probe is not a positive`() {
        assertEquals(DetectorStatus.allClear(), report(null).toDetectorStatus())
    }

    private fun report(secure: Boolean?, danger: Boolean = false) = SelinuxReport(
        stage = SelinuxStage.READY,
        mode = SelinuxMode.ENFORCING,
        resolvedStatusLabel = "Enforcing",
        filesystemMounted = true,
        paradoxDetected = false,
        methods = listOf(
            SelinuxCheckResult(
                method = SelinuxOracle.DIRTY_SEPOLICY_RAW.label,
                status = if (secure == false) "Invalid access result" else "Unavailable",
                isSecure = secure,
                permissionDenied = false,
                oracle = SelinuxOracle.DIRTY_SEPOLICY_RAW,
                dirtySepolicyDanger = danger,
            ),
        ),
        processContext = "u:r:untrusted_app:s0",
        contextType = "untrusted_app",
        policyAnalysis = null,
        auditIntegrity = null,
        androidVersion = "15",
        apiLevel = 35,
    )
}
