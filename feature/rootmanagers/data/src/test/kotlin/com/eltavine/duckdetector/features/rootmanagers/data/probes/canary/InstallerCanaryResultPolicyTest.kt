/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.features.rootmanagers.data.probes.canary

import com.eltavine.duckdetector.features.rootmanagers.domain.*

import org.junit.Assert.*
import org.junit.Test

class InstallerCanaryResultPolicyTest {
    private val host = "com.example.detector"
    private val group = "$host.installer_canary.missing"
    private val owner = "org.example.permissionowner"
    private val permission = InstallerCanaryTarget.PERMISSION
    private val duplicate = "INSTALL_FAILED_DUPLICATE_PERMISSION: Package $host attempting to redeclare permission $permission already owned by $owner"
    private val missing = "-127: Package $host attempting to declare permission $permission in non-existing group $group"
    private fun read(publicStatus: Int = 5, legacy: Int? = -112, message: String? = duplicate) =
        InstallerCanaryResultPolicy.interpret(host, group, publicStatus, legacy, message)

    @Test fun exactConflictRetainsUnverifiedOwnerWithoutInventingUser() {
        val result = read()
        assertEquals(InstallerCanaryState.PERMISSION_OWNER_OBSERVED, result.state)
        assertEquals(owner, result.ownerPackageName)
        assertTrue(result.locations.isEmpty())
    }

    @Test fun mismatchedStatusesAndMissingLegacyNeverProduceEvidence() {
        for (result in listOf(read(1), read(4), read(5, -7), read(5, null), read(message = null))) {
            assertEquals(InstallerCanaryState.INCONCLUSIVE, result.state)
            assertNull(result.ownerPackageName)
        }
    }

    @Test fun otherPermissionOtherHostAndMalformedOwnerAreRejected() {
        for (message in listOf(
            duplicate.replace(permission, "com.android.settings.BATTERY_DATA"),
            duplicate.replace(host, "com.example.other"),
            "$duplicate\ntrailing", duplicate.replace(owner, "../other"),
            duplicate.replace(owner, host), duplicate.replace(owner, "android"),
            "prefix $duplicate", "$duplicate ",
        )) assertEquals(InstallerCanaryState.INCONCLUSIVE, read(message = message).state)
    }

    @Test fun exactMissingGroupMeansConflictNotObserved() {
        assertEquals(InstallerCanaryState.PERMISSION_NOT_OBSERVED, read(1, -127, missing).state)
        assertEquals(InstallerCanaryState.INCONCLUSIVE, read(4, -127, missing).state)
        assertEquals(InstallerCanaryState.INCONCLUSIVE, read(1, -127, missing.replace(group, "another.group")).state)
    }

    @Test fun pendingUserActionAndUnexpectedSuccessNeverProduceOwner() {
        assertEquals(InstallerCanaryState.USER_ACTION_REQUIRED, read(-1).state)
        assertEquals(InstallerCanaryState.UNEXPECTED_SUCCESS, read(0).state)
        assertNull(read(0).ownerPackageName)
    }

    @Test fun observationAloneRemainsInformationalEvenWithoutEnumeration() {
        val report = RootManagersReport.unavailable("No accessible profiles").copy(installerCanary = read())
        assertEquals(RootManagersOutcome.PERMISSION_ANCHOR, report.outcome())
        assertEquals(com.eltavine.duckdetector.core.evidence.DetectorStatus.info(
            com.eltavine.duckdetector.core.evidence.InfoKind.SUPPORT), report.toDetectorStatus())
        assertTrue(report.entries.isEmpty())
        assertFalse(report.complete)
    }
}
