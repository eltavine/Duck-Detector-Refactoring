package com.eltavine.duckdetector.features.selinux.data.repository

import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxContextValiditySnapshot
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyRuleSet
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxLegacyDirtyPolicySemanticsTest {
    @Test fun `all seventeen preexisting rules keep their names and allowed result severity`() {
        val snapshot = SelinuxContextValiditySnapshot(
            javaDirtyPolicyAvailable = true,
            javaDirtyPolicyProbeAttempted = true,
            javaDirtyPolicyCarrierMatchesExpected = true,
            javaDirtyPolicyControlsPassed = true,
            javaDirtyPolicyStable = true,
            javaDirtyPolicyAccessControlAllowed = true,
            javaDirtyPolicyNegativeControlRejected = true,
            javaDirtyPolicySystemServerExecmemAllowed = true,
            javaDirtyPolicyFsckSysAdminAllowed = true,
            javaDirtyPolicyShellSuTransitionAllowed = true,
            javaDirtyPolicyAdbdAdbrootBinderCallAllowed = true,
            javaDirtyPolicyMagiskBinderCallAllowed = true,
            javaDirtyPolicyKsuFileReadAllowed = true,
            javaDirtyPolicyLsposedFileReadAllowed = true,
            javaDirtyPolicyMagiskDroidspacesdTransitionAllowed = true,
            javaDirtyPolicySuDroidspacesdTransitionAllowed = true,
            javaDirtyPolicySystemServerDroidspacesdBinderCallAllowed = true,
            javaDirtyPolicyMsdAppDaemonConnectAllowed = true,
            javaDirtyPolicyMsdDaemonSelfConnectAllowed = true,
            javaDirtyPolicyMsdDaemonSelinuxfsReadAllowed = true,
            javaDirtyPolicyMsdDaemonConfigfsDirSearchAllowed = true,
            javaDirtyPolicyMsdDaemonConfigfsFileWriteAllowed = true,
            javaDirtyPolicyXposedDataFileReadAllowed = true,
            javaDirtyPolicyZygoteAdbDataSearchAllowed = true,
        )
        val legacy = mapOf(
            "system_server execmem" to SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            "fsck_untrusted sys_admin" to SelinuxPolicyRuleSet.POLICY_OBSERVATION,
            "shell -> su transition" to SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            "adbd -> adbroot binder" to SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            "untrusted_app -> magisk binder" to SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            "untrusted_app -> ksu_file read" to SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            "untrusted_app -> lsposed_file read" to SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            "magisk -> droidspacesd dyntransition" to SelinuxPolicyRuleSet.DROIDSPACES,
            "su -> droidspacesd dyntransition" to SelinuxPolicyRuleSet.DROIDSPACES,
            "system_server -> droidspacesd binder" to SelinuxPolicyRuleSet.DROIDSPACES,
            "msd_app -> msd_daemon connectto" to SelinuxPolicyRuleSet.MSD,
            "msd_daemon -> msd_daemon connectto" to SelinuxPolicyRuleSet.MSD,
            "msd_daemon -> selinuxfs read" to SelinuxPolicyRuleSet.MSD,
            "msd_daemon -> configfs dir search" to SelinuxPolicyRuleSet.MSD,
            "msd_daemon -> configfs file write" to SelinuxPolicyRuleSet.MSD,
            "untrusted_app -> xposed_data read" to SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
            "zygote -> adb_data_file search" to SelinuxPolicyRuleSet.DIRTY_SEPOLICY,
        )
        val methods = buildDirtyPolicyMethods(snapshot)
        assertEquals(17, legacy.size)
        for ((edge, set) in legacy) {
            val result = methods.single { it.policyRule?.edge == edge }
            assertEquals(edge, set, result.policyRule?.set)
            assertEquals(edge, set.prefix + edge, result.method)
            assertEquals(edge, "Allowed", result.status)
            assertEquals(edge, if (set == SelinuxPolicyRuleSet.POLICY_OBSERVATION) null else false,
                result.isSecure)
            assertTrue(edge, result.dirtyPolicyTrusted)
        }
    }
}
