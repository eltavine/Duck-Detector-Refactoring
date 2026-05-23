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

import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValiditySnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxRepositoryDirtyPolicyMethodsTest {

    private val repository = SelinuxRepository()

    @Test
    fun `dirty policy methods expose explicit rule rows`() {
        val methods = repository.buildDirtyPolicyMethods(
            SelinuxContextValiditySnapshot(
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
                dirtyPolicyMagiskBinderCallAllowed = true,
                dirtyPolicyKsuFileReadAllowed = false,
                dirtyPolicyLsposedFileReadAllowed = true,
                dirtyPolicyMagiskDroidspacesdTransitionAllowed = true,
                dirtyPolicySuDroidspacesdTransitionAllowed = true,
                dirtyPolicySystemServerDroidspacesdBinderCallAllowed = true,
                dirtyPolicyMsdAppDaemonConnectAllowed = true,
                dirtyPolicyMsdDaemonSelfConnectAllowed = false,
                dirtyPolicyMsdDaemonSelinuxfsReadAllowed = true,
                dirtyPolicyMsdDaemonConfigfsDirSearchAllowed = true,
                dirtyPolicyMsdDaemonConfigfsFileWriteAllowed = true,
                dirtyPolicyXposedDataFileReadAllowed = false,
                dirtyPolicyZygoteAdbDataSearchAllowed = true,
                dirtyPolicyFailureReason = "shell -> su transition skipped on non-user build.",
                javaDirtyPolicyAvailable = true,
                javaDirtyPolicyProbeAttempted = true,
                javaDirtyPolicyCarrierContext = "u:r:app_zygote:s0:c1,c2",
                javaDirtyPolicyCarrierMatchesExpected = true,
                javaDirtyPolicyControlsPassed = true,
                javaDirtyPolicyStable = true,
                javaDirtyPolicyQueryMethod = "android.os.SELinux.checkSELinuxAccess",
                javaDirtyPolicyAccessControlAllowed = true,
                javaDirtyPolicyNegativeControlRejected = true,
                javaDirtyPolicySystemServerExecmemAllowed = true,
                javaDirtyPolicyMagiskBinderCallAllowed = true,
                javaDirtyPolicyLsposedFileReadAllowed = true,
                javaDirtyPolicyMagiskDroidspacesdTransitionAllowed = true,
                javaDirtyPolicySuDroidspacesdTransitionAllowed = true,
                javaDirtyPolicySystemServerDroidspacesdBinderCallAllowed = true,
                javaDirtyPolicyMsdAppDaemonConnectAllowed = true,
                javaDirtyPolicyMsdDaemonSelfConnectAllowed = false,
                javaDirtyPolicyMsdDaemonSelinuxfsReadAllowed = true,
                javaDirtyPolicyMsdDaemonConfigfsDirSearchAllowed = true,
                javaDirtyPolicyMsdDaemonConfigfsFileWriteAllowed = true,
            ),
        )

        assertEquals(17, methods.size)
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: system_server execmem" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: system_server execmem" && it.dirtyPolicyTrusted })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: fsck_untrusted sys_admin" && it.status == "Denied" && it.isSecure == true })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: shell -> su transition" && it.status == "Unavailable" && it.isSecure == null })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: adbd -> adbroot binder" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: untrusted_app -> magisk binder" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: untrusted_app -> ksu_file read" && it.status == "Denied" && it.isSecure == true })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: untrusted_app -> lsposed_file read" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "Droidspaces checker: magisk -> droidspacesd dyntransition" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "Droidspaces checker: su -> droidspacesd dyntransition" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "Droidspaces checker: system_server -> droidspacesd binder" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: untrusted_app -> xposed_data read" && it.status == "Denied" && it.isSecure == true })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: zygote -> adb_data_file search" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "MSD checker: msd_app -> msd_daemon connectto" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "MSD checker: msd_daemon -> msd_daemon connectto" && it.status == "Denied" && it.isSecure == true })
        assertTrue(methods.any { it.method == "MSD checker: msd_daemon -> selinuxfs read" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "MSD checker: msd_daemon -> configfs dir search" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "MSD checker: msd_daemon -> configfs file write" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: system_server execmem" && it.details.orEmpty().contains("Native dedicated=") && it.details.orEmpty().contains("Java dedicated=") })
        assertTrue(
            methods.any {
                it.method == "Dirty sepolicy rule: untrusted_app -> ksu_file read" &&
                    it.details.orEmpty().contains("Observed edge: untrusted_app -> ksu_file:file read.")
            },
        )
        assertTrue(
            methods.any {
                it.method == "Dirty sepolicy rule: untrusted_app -> lsposed_file read" &&
                    it.details.orEmpty().contains("Observed edge: untrusted_app -> lsposed_file:file read.")
            },
        )
    }

    @Test
    fun `unstable dirty policy oracle downgrades all rule rows to unavailable`() {
        val methods = repository.buildDirtyPolicyMethods(
            SelinuxContextValiditySnapshot(
                dirtyPolicyAvailable = true,
                dirtyPolicyProbeAttempted = true,
                dirtyPolicyCarrierContext = "u:r:app_zygote:s0:c1,c2",
                dirtyPolicyCarrierMatchesExpected = true,
                dirtyPolicyControlsPassed = true,
                dirtyPolicyStable = false,
                dirtyPolicyQueryMethod = "android.os.SELinux.checkSELinuxAccess",
                dirtyPolicyAccessControlAllowed = true,
                dirtyPolicyNegativeControlRejected = true,
                dirtyPolicySystemServerExecmemAllowed = true,
                dirtyPolicyFsckSysAdminAllowed = true,
                dirtyPolicyShellSuTransitionAllowed = true,
                dirtyPolicyAdbdAdbrootBinderCallAllowed = true,
                dirtyPolicyMagiskBinderCallAllowed = true,
                dirtyPolicyKsuFileReadAllowed = true,
                dirtyPolicyLsposedFileReadAllowed = true,
                dirtyPolicyMagiskDroidspacesdTransitionAllowed = true,
                dirtyPolicySuDroidspacesdTransitionAllowed = true,
                dirtyPolicySystemServerDroidspacesdBinderCallAllowed = true,
                dirtyPolicyXposedDataFileReadAllowed = true,
                dirtyPolicyZygoteAdbDataSearchAllowed = true,
                dirtyPolicyFailureReason = "Dirty policy oracle self-test failed.",
            ),
        )

        assertEquals(17, methods.size)
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: system_server execmem" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: untrusted_app -> lsposed_file read" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.none { it.dirtyPolicyTrusted })
    }

    @Test
    fun `stable dirty policy rules remain visible even when controls fail`() {
        val methods = repository.buildDirtyPolicyMethods(
            SelinuxContextValiditySnapshot(
                dirtyPolicyAvailable = true,
                dirtyPolicyProbeAttempted = true,
                dirtyPolicyCarrierContext = "u:r:app_zygote:s0:c1,c2",
                dirtyPolicyCarrierMatchesExpected = true,
                dirtyPolicyControlsPassed = false,
                dirtyPolicyStable = true,
                dirtyPolicyQueryMethod = "android.os.SELinux.checkSELinuxAccess",
                dirtyPolicyAccessControlAllowed = false,
                dirtyPolicyNegativeControlRejected = false,
                dirtyPolicySystemServerExecmemAllowed = true,
                dirtyPolicyFsckSysAdminAllowed = false,
                dirtyPolicyShellSuTransitionAllowed = null,
                dirtyPolicyAdbdAdbrootBinderCallAllowed = false,
                dirtyPolicyMagiskBinderCallAllowed = true,
                dirtyPolicyKsuFileReadAllowed = true,
                dirtyPolicyLsposedFileReadAllowed = false,
                dirtyPolicyMagiskDroidspacesdTransitionAllowed = true,
                dirtyPolicyXposedDataFileReadAllowed = false,
                dirtyPolicyZygoteAdbDataSearchAllowed = true,
                dirtyPolicyFailureReason = "Dirty policy oracle self-test failed.",
            ),
        )

        assertTrue(methods.any { it.method == "Dirty sepolicy rule: system_server execmem" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.any { it.method == "Dirty sepolicy rule: fsck_untrusted sys_admin" && it.status == "Denied" && it.isSecure == true })
        assertTrue(methods.any { it.method == "Droidspaces checker: magisk -> droidspacesd dyntransition" && it.status == "Allowed" && it.isSecure == false })
        assertTrue(methods.none { it.dirtyPolicyTrusted })
        assertTrue(methods.any { it.details.orEmpty().contains("reason=Dirty policy oracle self-test failed.") })
    }

    @Test
    fun `conflicting native and java dirty policy verdicts do not collapse to allowed`() {
        val methods = repository.buildDirtyPolicyMethods(
            SelinuxContextValiditySnapshot(
                dirtyPolicyAvailable = true,
                dirtyPolicyProbeAttempted = true,
                dirtyPolicyCarrierContext = "u:r:app_zygote:s0:c1,c2",
                dirtyPolicyCarrierMatchesExpected = true,
                dirtyPolicyControlsPassed = true,
                dirtyPolicyStable = true,
                dirtyPolicyQueryMethod = "selinux_check_access",
                dirtyPolicyAccessControlAllowed = true,
                dirtyPolicyNegativeControlRejected = true,
                dirtyPolicyLsposedFileReadAllowed = true,
                javaDirtyPolicyAvailable = true,
                javaDirtyPolicyProbeAttempted = true,
                javaDirtyPolicyCarrierContext = "u:r:app_zygote:s0:c1,c2",
                javaDirtyPolicyCarrierMatchesExpected = true,
                javaDirtyPolicyControlsPassed = true,
                javaDirtyPolicyStable = true,
                javaDirtyPolicyQueryMethod = "android.os.SELinux.checkSELinuxAccess",
                javaDirtyPolicyAccessControlAllowed = true,
                javaDirtyPolicyNegativeControlRejected = true,
                javaDirtyPolicyLsposedFileReadAllowed = false,
            ),
        )

        val method = methods.single { it.method == "Dirty sepolicy rule: untrusted_app -> lsposed_file read" }
        assertEquals("Unavailable", method.status)
        assertEquals(null, method.isSecure)
        assertEquals(false, method.dirtyPolicyTrusted)
        assertTrue(method.details.orEmpty().contains("tracks disagreed"))
    }
}
