package com.eltavine.duckdetector.features.selinux.data.repository

import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxContextValiditySnapshot
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxDirtySepolicyRawSnapshot
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxDirtySepolicyRawState
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxRawContextCollectionState
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxDirtySepolicyCompatibilityResult
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxDirtySepolicyCompatibilityVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxDirtySepolicyRawMethodsTest {
    @Test
    fun `new DirtySepolicy 2 point 2 rules are warning only without changing original rules`() {
        val snapshot = SelinuxContextValiditySnapshot(
            javaDirtyPolicyAvailable = true,
            javaDirtyPolicyProbeAttempted = true,
            javaDirtyPolicyCarrierMatchesExpected = true,
            javaDirtyPolicyControlsPassed = true,
            javaDirtyPolicyStable = true,
            javaDirtyPolicyAccessControlAllowed = true,
            javaDirtyPolicyNegativeControlRejected = true,
            javaDirtyPolicySystemServerExecmemAllowed = true,
            javaDirtyPolicyAdditionalRules = mapOf(
                "rootfs -> tmpfs associate" to true,
                "kernel -> tmpfs fifo open" to true,
                "kernel -> adb_data_file read" to true,
            ),
        )
        val methods = buildDirtyPolicyMethods(snapshot)
        for (edge in listOf("rootfs -> tmpfs associate", "kernel -> tmpfs fifo open",
            "kernel -> adb_data_file read")) {
            val method = methods.single { it.policyRule?.edge == edge }
            assertEquals(edge, true, method.dirtySepolicyWarningOnly)
            assertEquals(edge, false, method.isSecure)
            assertEquals(edge, true, method.dirtyPolicyTrusted)
        }
        val legacy = methods.single { it.policyRule?.edge == "system_server execmem" }
        assertEquals(false, legacy.dirtySepolicyWarningOnly)
        assertEquals(false, legacy.isSecure)
        assertEquals(true, legacy.dirtyPolicyTrusted)
    }

    @Test
    fun `original protocol errors are danger independent of unrelated raw probe state`() {
        for (reason in listOf("unknown status version: 2", "cannot check SELinux access",
            "PID context mismatch or unreadable", "read_status failed or status header unavailable",
            "avdSeqNo access failed or malformed")) {
            val result = buildDirtyPolicyAccessProtocolMethod(SelinuxContextValiditySnapshot(
                dirtySepolicyRaw = SelinuxDirtySepolicyRawSnapshot(
                    state = SelinuxDirtySepolicyRawState.UNTRUSTED,
                    compatibility = SelinuxDirtySepolicyCompatibilityResult(
                        SelinuxDirtySepolicyCompatibilityVerdict.ERROR, listOf(reason)),
                ),
            ))
            assertEquals("DirtySepolicy ERROR", result.status)
            assertEquals(false, result.isSecure)
            assertEquals(true, result.dirtySepolicyDanger)
            assertTrue(result.details.orEmpty().contains(reason))
        }
    }

    @Test
    fun `original warnings include OEM dependent policy rules without changing Duck rule attribution`() {
        val result = buildDirtyPolicyAccessProtocolMethod(SelinuxContextValiditySnapshot(
            dirtySepolicyRaw = SelinuxDirtySepolicyRawSnapshot(
                state = SelinuxDirtySepolicyRawState.COMPLETE,
                allowedRules = listOf("system_server execmem"),
                warningRules = emptyList(),
                compatibility = SelinuxDirtySepolicyCompatibilityResult(
                    SelinuxDirtySepolicyCompatibilityVerdict.WARNING,
                    listOf("system_server can execmem", "avdSeqNo=2")),
            ),
        ))
        assertEquals("DirtySepolicy WARNING", result.status)
        assertEquals(false, result.isSecure)
        assertEquals(true, result.dirtySepolicyDanger)
        assertTrue(result.details.orEmpty().contains("avdSeqNo=2"))
    }

    @Test
    fun `inconclusive compatibility does not suppress unrelated trusted context positives`() {
        val result = buildDirtyPolicyAccessProtocolMethod(SelinuxContextValiditySnapshot(
            dirtySepolicyRaw = SelinuxDirtySepolicyRawSnapshot(
                state = SelinuxDirtySepolicyRawState.PARTIAL,
                recognizedContexts = listOf("u:r:ksu:s0"),
                compatibility = SelinuxDirtySepolicyCompatibilityResult(
                    SelinuxDirtySepolicyCompatibilityVerdict.INCONCLUSIVE,
                    listOf("policy epoch changed")),
            ),
        ))
        assertEquals(false, result.isSecure)
        assertEquals("Root contexts observed", result.status)
        assertEquals(false, result.dirtySepolicyDanger)
    }
    @Test
    fun `Native and Java use the same eligibility for six original DirtySepolicy edges`() {
        val extras = mapOf(
            "rootfs -> tmpfs associate" to true,
            "kernel -> tmpfs fifo open" to true,
            "kernel -> adb_data_file read" to true,
        )
        val native = SelinuxContextValiditySnapshot(
            dirtyPolicyAvailable = true,
            dirtyPolicyProbeAttempted = true,
            dirtyPolicyCarrierMatchesExpected = true,
            dirtyPolicyControlsPassed = true,
            dirtyPolicyStable = true,
            dirtyPolicyAccessControlAllowed = true,
            dirtyPolicyNegativeControlRejected = true,
            dirtyPolicyShellSuTransitionAllowed = true,
            dirtyPolicyAdbdAdbrootBinderCallAllowed = true,
            dirtyPolicyZygoteAdbDataSearchAllowed = true,
            dirtyPolicyAdditionalRules = extras,
        )
        val java = SelinuxContextValiditySnapshot(
            javaDirtyPolicyAvailable = true,
            javaDirtyPolicyProbeAttempted = true,
            javaDirtyPolicyCarrierMatchesExpected = true,
            javaDirtyPolicyControlsPassed = true,
            javaDirtyPolicyStable = true,
            javaDirtyPolicyAccessControlAllowed = true,
            javaDirtyPolicyNegativeControlRejected = true,
            javaDirtyPolicyShellSuTransitionAllowed = true,
            javaDirtyPolicyAdbdAdbrootBinderCallAllowed = true,
            javaDirtyPolicyZygoteAdbDataSearchAllowed = true,
            javaDirtyPolicyAdditionalRules = extras,
        )
        for (snapshot in listOf(native, java)) {
            for (edge in extras.keys + listOf("shell -> su transition", "adbd -> adbroot binder",
                "zygote -> adb_data_file search")) {
                val result = buildDirtyPolicyMethods(snapshot).single { it.policyRule?.edge == edge }
                assertEquals(edge, com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
                    result.policyRule?.set)
                assertEquals(edge, false, result.isSecure)
            }
        }
    }
    @Test
    fun `context finding survives untrusted access controls`() {
        val result = buildDirtyPolicyAccessProtocolMethod(SelinuxContextValiditySnapshot(
            dirtySepolicyRaw = SelinuxDirtySepolicyRawSnapshot(
                state = SelinuxDirtySepolicyRawState.UNTRUSTED,
                controlsPassed = false,
                contextControlsPassed = true,
                recognizedContexts = listOf("u:object_r:xposed_file:s0"),
            ),
        ))
        assertEquals(false, result.isSecure)
        assertEquals("Root contexts observed", result.status)
    }

    @Test
    fun `status finding survives untrusted access and cannot be suppressed by it`() {
        val result = buildDirtyPolicyAccessProtocolMethod(SelinuxContextValiditySnapshot(
            dirtySepolicyRaw = SelinuxDirtySepolicyRawSnapshot(
                state = SelinuxDirtySepolicyRawState.UNTRUSTED,
                controlsPassed = false,
                statusWarnings = listOf("Status header deny_unknown=0"),
            ),
        ))
        assertEquals(false, result.isSecure)
        assertEquals("Status header anomaly", result.status)
    }

    @Test
    fun `untrusted access and untrusted context are not findings`() {
        val result = buildDirtyPolicyAccessProtocolMethod(SelinuxContextValiditySnapshot(
            dirtySepolicyRaw = SelinuxDirtySepolicyRawSnapshot(
                state = SelinuxDirtySepolicyRawState.UNTRUSTED,
                controlsPassed = false,
                contextControlsPassed = false,
            ),
        ))
        assertNull(result.isSecure)
    }

    @Test
    fun `complete access with incomplete context visibly reports context coverage`() {
        val result = buildDirtyPolicyAccessProtocolMethod(SelinuxContextValiditySnapshot(
            dirtySepolicyRaw = SelinuxDirtySepolicyRawSnapshot(
                state = SelinuxDirtySepolicyRawState.COMPLETE,
                controlsPassed = true,
                contextCollection = SelinuxRawContextCollectionState.PARTIAL,
            ),
        ))
        assertEquals("Context partially collected", result.status)
        assertNull(result.isSecure)
        assertTrue(result.details.orEmpty().contains("Access collection=COMPLETE; context collection=PARTIAL"))
    }
    @Test
    fun `trusted allowed raw edge becomes a warning candidate`() {
        val snapshot = SelinuxContextValiditySnapshot(
            dirtySepolicyRaw = SelinuxDirtySepolicyRawSnapshot(
                state = SelinuxDirtySepolicyRawState.COMPLETE,
                controlsPassed = true,
                stable = true,
                allowedRules = listOf("untrusted_app -> ksu_file read"),
                warningRules = listOf("untrusted_app -> ksu_file read"),
            ),
        )
        val method = buildDirtyPolicyAccessProtocolMethod(snapshot)
        assertEquals(false, method.isSecure)
        assertEquals("Allowed rules observed", method.status)
        assertTrue(method.details.orEmpty().contains("Trusted raw allows="))
    }

    @Test
    fun `controlled context hit can warn without an allowed access rule`() {
        val result = buildDirtyPolicyAccessProtocolMethod(SelinuxContextValiditySnapshot(
            dirtySepolicyRaw = SelinuxDirtySepolicyRawSnapshot(
                state = SelinuxDirtySepolicyRawState.COMPLETE,
                contextControlsPassed = true,
                recognizedContexts = listOf("u:object_r:xposed_file:s0"),
            ),
        ))
        assertEquals("Root contexts observed", result.status)
        assertEquals(false, result.isSecure)
    }
    @Test
    fun `previously missing edge reuses existing two track trust gate`() {
        val snapshot = SelinuxContextValiditySnapshot(
            dirtyPolicyAvailable = true,
            dirtyPolicyProbeAttempted = true,
            dirtyPolicyCarrierMatchesExpected = true,
            dirtyPolicyControlsPassed = true,
            dirtyPolicyStable = true,
            dirtyPolicyAccessControlAllowed = true,
            dirtyPolicyNegativeControlRejected = true,
            dirtyPolicyAdditionalRules = mapOf("kernel -> adb_data_file read" to true),
            javaDirtyPolicyAvailable = true,
            javaDirtyPolicyProbeAttempted = true,
            javaDirtyPolicyCarrierMatchesExpected = true,
            javaDirtyPolicyControlsPassed = true,
            javaDirtyPolicyStable = true,
            javaDirtyPolicyAccessControlAllowed = true,
            javaDirtyPolicyNegativeControlRejected = true,
            javaDirtyPolicyAdditionalRules = mapOf("kernel -> adb_data_file read" to true),
        )
        val hit = buildDirtyPolicyMethods(snapshot).single { it.method == "Dirty sepolicy rule: kernel -> adb_data_file read" }
        assertEquals(false, hit.isSecure)
        assertEquals(true, hit.dirtyPolicyTrusted)
        val discrepancy = buildDirtyPolicyMethods(
            snapshot.copy(javaDirtyPolicyAdditionalRules = mapOf("kernel -> adb_data_file read" to false)),
        ).single { it.method == hit.method }
        assertNull(discrepancy.isSecure)
        assertEquals(false, discrepancy.dirtyPolicyTrusted)
    }

    @Test
    fun `dex2oat execute no trans is policy observation not a dirty policy finding`() {
        val snapshot = SelinuxContextValiditySnapshot(
            javaDirtyPolicyAvailable = true,
            javaDirtyPolicyProbeAttempted = true,
            javaDirtyPolicyCarrierMatchesExpected = true,
            javaDirtyPolicyControlsPassed = true,
            javaDirtyPolicyStable = true,
            javaDirtyPolicyAccessControlAllowed = true,
            javaDirtyPolicyNegativeControlRejected = true,
            javaDirtyPolicyAdditionalRules = mapOf("dex2oat -> dex2oat_exec execute_no_trans" to true),
        )
        val method = buildDirtyPolicyMethods(snapshot)
            .single { it.method.endsWith("dex2oat -> dex2oat_exec execute_no_trans") }
        assertEquals("Allowed", method.status)
        assertNull(method.isSecure)
        assertEquals(com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyRuleSet.POLICY_OBSERVATION, method.policyRule?.set)
    }

    @Test
    fun `preexisting system server execmem remains a dirty policy finding while new APK edge is informational`() {
        val snapshot = SelinuxContextValiditySnapshot(
            javaDirtyPolicyAvailable = true,
            javaDirtyPolicyProbeAttempted = true,
            javaDirtyPolicyCarrierMatchesExpected = true,
            javaDirtyPolicyControlsPassed = true,
            javaDirtyPolicyStable = true,
            javaDirtyPolicyAccessControlAllowed = true,
            javaDirtyPolicyNegativeControlRejected = true,
            javaDirtyPolicySystemServerExecmemAllowed = true,
            javaDirtyPolicyAdditionalRules = mapOf("system_server -> apk_data_file execute" to true),
        )
        val methods = buildDirtyPolicyMethods(snapshot)
        val existing = methods.single { it.policyRule?.edge == "system_server execmem" }
        assertEquals("Allowed", existing.status)
        assertEquals(false, existing.isSecure)
        assertEquals(com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            existing.policyRule?.set)
        val added = methods.single { it.policyRule?.edge == "system_server -> apk_data_file execute" }
        assertEquals("Allowed", added.status)
        assertNull(added.isSecure)
        assertEquals(com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyRuleSet.POLICY_OBSERVATION,
            added.policyRule?.set)
    }

    @Test
    fun `invalid access response is warning evidence on original dirty policy flow`() {
        val result = buildDirtyPolicyAccessProtocolMethod(
            SelinuxContextValiditySnapshot(
                dirtySepolicyRaw = SelinuxDirtySepolicyRawSnapshot(
                    state = SelinuxDirtySepolicyRawState.INVALID_ACCESS_RESULT,
                    rawResponse = "10000 ffffffff 0 ffffff",
                ),
            ),
        )
        assertEquals(false, result.isSecure)
        assertEquals("Invalid access result", result.status)
    }

    @Test
    fun `unavailable raw response does not count as a hit`() {
        assertNull(buildDirtyPolicyAccessProtocolMethod(SelinuxContextValiditySnapshot()).isSecure)
    }
}
