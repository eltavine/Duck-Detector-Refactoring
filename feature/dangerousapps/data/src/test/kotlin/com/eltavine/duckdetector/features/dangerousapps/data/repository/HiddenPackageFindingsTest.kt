// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.features.dangerousapps.data.repository

import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppFinding
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsCatalog
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousDetectionMethod
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousDetectionMethodKind
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HiddenPackageFindingsTest {
    private val target = DangerousAppsCatalog.targets.single { it.packageName == "github.tornaco.android.thanos" }

    @Test fun `runtime IPC alone never establishes a hidden package`() {
        val finding = finding(DangerousDetectionMethodKind.THANOX_IPC)
        assertTrue(hiddenPackageFindings(listOf(finding), emptySet(), DangerousPackageVisibility.FULL).isEmpty())
    }

    @Test fun `package evidence still establishes a visibility discrepancy`() {
        val finding = finding(DangerousDetectionMethodKind.THANOX_IPC, DangerousDetectionMethodKind.OPEN_APK_FD)
        assertEquals(listOf(finding), hiddenPackageFindings(listOf(finding), emptySet(), DangerousPackageVisibility.FULL))
    }

    @Test fun `visible packages are not hidden`() {
        val finding = finding(DangerousDetectionMethodKind.OPEN_APK_FD)
        assertTrue(hiddenPackageFindings(listOf(finding), setOf(target.packageName), DangerousPackageVisibility.FULL).isEmpty())
    }

    @Test fun `restricted or unknown inventory cannot establish concealment`() {
        val finding = finding(DangerousDetectionMethodKind.OPEN_APK_FD)
        for (visibility in listOf(DangerousPackageVisibility.RESTRICTED, DangerousPackageVisibility.UNKNOWN)) {
            assertTrue(hiddenPackageFindings(listOf(finding), emptySet(), visibility).isEmpty())
        }
    }

    @Test fun `excluded path evidence stays ineligible`() {
        val finding = DangerousAppFinding(target, listOf(
            DangerousDetectionMethod(DangerousDetectionMethodKind.THANOX_IPC),
            DangerousDetectionMethod(DangerousDetectionMethodKind.SPECIAL_PATH, hmaEligible = false),
        ))
        assertTrue(hiddenPackageFindings(listOf(finding), emptySet(), DangerousPackageVisibility.FULL).isEmpty())
    }

    private fun finding(vararg kinds: DangerousDetectionMethodKind) =
        DangerousAppFinding(target, kinds.map { DangerousDetectionMethod(it) })
}
