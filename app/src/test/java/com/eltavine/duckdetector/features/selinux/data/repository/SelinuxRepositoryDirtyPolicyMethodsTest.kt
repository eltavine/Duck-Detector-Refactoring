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

package com.eltavine.duckdetector.features.selinux.data.repository

import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxContextValidityProbeResult
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxContextValidityState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxRepositoryDirtyPolicyMethodsTest {

    private val repository = SelinuxRepository()

    @Test
    fun `dirty policy methods expose explicit rule rows`() {
        val methods = repository.buildDirtyPolicyMethods(
            SelinuxContextValidityProbeResult(
                state = SelinuxContextValidityState.CLEAN,
                available = true,
                probeAttempted = true,
                carrierContext = "u:r:app_zygote:s0:c1,c2",
                carrierMatchesExpected = true,
                selinuxEnabled = true,
                selinuxEnforced = true,
                pidContextMatchesCurrent = true,
                procSelfContextMatchesCurrent = true,
                dyntransitionCheckPassed = true,
                carrierControlValid = true,
                negativeControlRejected = true,
                fileControlValid = true,
                fileNegativeControlRejected = true,
                oracleControlsPassed = true,
                ksuResultsStable = true,
                queryMethod = "raw selinuxfs write",
                ksuDomainValid = false,
                ksuFileValid = false,
                bitPair = "00",
                dirtyPolicyAvailable = true,
                dirtyPolicyProbeAttempted = true,
                dirtyPolicyCarrierContext = "u:r:app_zygote:s0:c1,c2",
                dirtyPolicyCarrierMatchesExpected = true,
                dirtyPolicyControlsPassed = true,
                dirtyPolicyStable = true,
                dirtyPolicyQueryMethod = "android.os.SELinux.checkSELinuxAccess",
                dirtyPolicyAccessControlAllowed = true,
                dirtyPolicyNegativeControlRejected = true,
                dirtyPolicySystemServerExecmemAllowed = true,
                dirtyPolicyFsckSysAdminAllowed = false,
                dirtyPolicyShellSuTransitionAllowed = null,
                dirtyPolicyAdbdAdbrootBinderCallAllowed = true,
                dirtyPolicyMagiskBinderCallAllowed = false,
                dirtyPolicyKsuFileReadAllowed = false,
                dirtyPolicyLsposedFileReadAllowed = true,
                dirtyPolicyXposedDataFileReadAllowed = false,
                dirtyPolicyZygoteAdbDataSearchAllowed = true,
                dirtyPolicyFailureReason = "shell -> su transition skipped on non-user build.",
                dirtyPolicyNotes = emptyList(),
                procAttrCurrentProbeAttempted = false,
                procAttrCurrentResults = emptyList(),
                procAttrCurrentFailureReason = null,
                failureReason = null,
                notes = emptyList(),
            ),
        )

        assertEquals(9, methods.size)
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: system_server execmem" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: fsck_untrusted sys_admin" && it.status == "Denied" && it.isSecure == true })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: shell -> su transition" && it.status == "Unavailable" && it.isSecure == null })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: adbd -> adbroot binder" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: untrusted_app -> magisk binder" && it.status == "Denied" && it.isSecure == true })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: untrusted_app -> ksu_file read" && it.status == "Denied" && it.isSecure == true })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: untrusted_app -> lsposed_file read" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: untrusted_app -> xposed_data read" && it.status == "Denied" && it.isSecure == true })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: zygote -> adb_data_file search" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: system_server execmem" && it.details.orEmpty().contains("Evidence source=dedicated app_zygote carrier") && it.details.orEmpty().contains("Observed edge:") })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: shell -> su transition" && it.details.orEmpty().contains("Reason:") })
    }

    @Test
    fun `untrusted dirty policy oracle downgrades all rule rows to unavailable`() {
        val methods = repository.buildDirtyPolicyMethods(
            SelinuxContextValidityProbeResult(
                state = SelinuxContextValidityState.CLEAN,
                available = true,
                probeAttempted = true,
                carrierContext = "u:r:app_zygote:s0:c1,c2",
                carrierMatchesExpected = true,
                selinuxEnabled = true,
                selinuxEnforced = true,
                pidContextMatchesCurrent = true,
                procSelfContextMatchesCurrent = true,
                dyntransitionCheckPassed = true,
                carrierControlValid = true,
                negativeControlRejected = true,
                fileControlValid = true,
                fileNegativeControlRejected = true,
                oracleControlsPassed = true,
                ksuResultsStable = true,
                queryMethod = "raw selinuxfs write",
                ksuDomainValid = false,
                ksuFileValid = false,
                bitPair = "00",
                dirtyPolicyAvailable = true,
                dirtyPolicyProbeAttempted = true,
                dirtyPolicyCarrierContext = "u:r:app_zygote:s0:c1,c2",
                dirtyPolicyCarrierMatchesExpected = true,
                dirtyPolicyControlsPassed = false,
                dirtyPolicyStable = false,
                dirtyPolicyQueryMethod = "android.os.SELinux.checkSELinuxAccess",
                dirtyPolicyAccessControlAllowed = false,
                dirtyPolicyNegativeControlRejected = false,
                dirtyPolicySystemServerExecmemAllowed = true,
                dirtyPolicyFsckSysAdminAllowed = true,
                dirtyPolicyShellSuTransitionAllowed = true,
                dirtyPolicyAdbdAdbrootBinderCallAllowed = true,
                dirtyPolicyMagiskBinderCallAllowed = true,
                dirtyPolicyKsuFileReadAllowed = true,
                dirtyPolicyLsposedFileReadAllowed = true,
                dirtyPolicyXposedDataFileReadAllowed = true,
                dirtyPolicyZygoteAdbDataSearchAllowed = true,
                dirtyPolicyFailureReason = "Dirty policy oracle self-test failed.",
                dirtyPolicyNotes = emptyList(),
                procAttrCurrentProbeAttempted = false,
                procAttrCurrentResults = emptyList(),
                procAttrCurrentFailureReason = null,
                failureReason = null,
                notes = emptyList(),
            ),
        )

        assertEquals(9, methods.size)
        assertTrue(methods.all { it.status == "Unavailable" && it.isSecure == null })
    }
}
