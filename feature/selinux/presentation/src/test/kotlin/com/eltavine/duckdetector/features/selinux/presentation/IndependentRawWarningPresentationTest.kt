package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.features.selinux.domain.*
import org.junit.Assert.assertEquals
import org.junit.Test

class IndependentRawWarningPresentationTest {
    @Test fun newDirtySepolicyRuleIsYellowWhileOriginalRuleIsStillRed() {
        val newRule = SelinuxCheckResult(
            method = "Dirty sepolicy rule: kernel -> adb_data_file read", status = "Allowed",
            isSecure = false, permissionDenied = false, dirtyPolicyTrusted = true,
            dirtySepolicyWarningOnly = true,
            policyRule = SelinuxPolicyRule(SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
                "kernel -> adb_data_file read", SelinuxRuleVerdict.ALLOWED),
        )
        val oldRule = SelinuxCheckResult(
            method = "Dirty sepolicy rule: system_server execmem", status = "Allowed",
            isSecure = false, permissionDenied = false, dirtyPolicyTrusted = true,
            policyRule = SelinuxPolicyRule(SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
                "system_server execmem", SelinuxRuleVerdict.ALLOWED),
        )
        val report = SelinuxReport.loading().copy(
            stage = SelinuxStage.READY, mode = SelinuxMode.ENFORCING, methods = listOf(newRule),
        )
        val newModel = SelinuxCardModelMapper().map(report)
        assertEquals(DetectorStatus.warning(), newModel.status)
        assertEquals(DetectorStatus.warning(), newModel.methodRows.single().status)
        val oldModel = SelinuxCardModelMapper().map(report.copy(methods = listOf(oldRule)))
        assertEquals(DetectorStatus.warning(), oldModel.status)
        assertEquals(DetectorStatus.danger(), oldModel.methodRows.single().status)
        val both = SelinuxCardModelMapper().map(report.copy(methods = listOf(oldRule, newRule)))
        assertEquals(DetectorStatus.danger(), both.methodRows.first().status)
        assertEquals(DetectorStatus.warning(), both.methodRows.last().status)
    }

    @Test fun invalidAccessIsDangerInCardAndDetailRow() {
        val report = SelinuxReport.loading().copy(
            stage = SelinuxStage.READY, mode = SelinuxMode.ENFORCING,
            methods = listOf(SelinuxCheckResult(
                method = SelinuxOracle.DIRTY_SEPOLICY_RAW.label,
                status = "Invalid access result", isSecure = false,
                permissionDenied = false, oracle = SelinuxOracle.DIRTY_SEPOLICY_RAW,
                dirtySepolicyDanger = true)))
        assertEquals(DetectorStatus.danger(), report.toDetectorStatus())
        assertEquals(DetectorStatus.danger(), buildMethodRows(report).single().status)
    }

    @Test fun independentDangerDoesNotEscalateOrdinaryRawWarning() {
        val report = SelinuxReport.loading().copy(
            stage = SelinuxStage.READY, mode = SelinuxMode.PERMISSIVE,
            methods = listOf(SelinuxCheckResult(
                method = SelinuxOracle.DIRTY_SEPOLICY_RAW.label,
                status = "Root contexts observed", isSecure = false,
                permissionDenied = false, oracle = SelinuxOracle.DIRTY_SEPOLICY_RAW)),
        )
        assertEquals(DetectorStatus.danger(), report.toDetectorStatus())
        assertEquals(DetectorStatus.warning(), buildMethodRows(report).single().status)
    }

    @Test fun controlledInterfaceDisagreementIsDangerInCardAndMethodRow() {
        val report = SelinuxReport.loading().copy(
            stage = SelinuxStage.READY, mode = SelinuxMode.ENFORCING,
            methods = listOf(SelinuxCheckResult(
                method = SelinuxOracle.DIRTY_SEPOLICY_RAW.label,
                status = "Raw/API disagreement", isSecure = false,
                permissionDenied = false, oracle = SelinuxOracle.DIRTY_SEPOLICY_RAW,
                dirtySepolicyDanger = true,
            )),
        )
        val model = SelinuxCardModelMapper().map(report)
        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals(DetectorStatus.danger(), model.methodRows.single().status)
        assertEquals("Enforcing with DirtySepolicy anomaly", model.verdict)
        val unknown = SelinuxCardModelMapper().map(report.copy(mode = SelinuxMode.UNKNOWN))
        assertEquals(DetectorStatus.danger(), unknown.status)
        assertEquals("SELinux mode unknown with DirtySepolicy anomaly", unknown.verdict)
    }

    @Test fun originalSeqnoDangerStillOutranksNewRawDangerHeadline() {
        val report = SelinuxReport.loading().copy(
            stage = SelinuxStage.READY, mode = SelinuxMode.ENFORCING,
            methods = listOf(
                SelinuxCheckResult(SelinuxOracle.POLICYLOAD_SEQNO.label, "Seqno split", false, false,
                    oracle = SelinuxOracle.POLICYLOAD_SEQNO),
                SelinuxCheckResult(SelinuxOracle.DIRTY_SEPOLICY_RAW.label, "Raw/API disagreement", false, false,
                    oracle = SelinuxOracle.DIRTY_SEPOLICY_RAW, dirtySepolicyDanger = true),
            ),
        )
        val model = SelinuxCardModelMapper().map(report)
        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals(DetectorStatus.danger(), model.methodRows.first().status)
        assertEquals(DetectorStatus.danger(), model.methodRows.last().status)
        assertEquals("Enforcing with app_zygote seqno split", model.verdict)
    }
}
