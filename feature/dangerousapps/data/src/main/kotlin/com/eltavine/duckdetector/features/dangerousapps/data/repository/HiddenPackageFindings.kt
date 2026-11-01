// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.features.dangerousapps.data.repository

import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppFinding
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousDetectionMethodKind
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility

internal fun hiddenPackageFindings(
    findings: List<DangerousAppFinding>,
    installedPackages: Set<String>,
    visibility: DangerousPackageVisibility,
): List<DangerousAppFinding> {
    if (visibility != DangerousPackageVisibility.FULL) return emptyList()
    return findings.filter { finding ->
        finding.target.packageName !in installedPackages && finding.methods.any { method ->
            method.hmaEligible && method.kind != DangerousDetectionMethodKind.PACKAGE_MANAGER &&
                // A runtime interface does not establish installation of the manager APK.
                method.kind != DangerousDetectionMethodKind.THANOX_IPC
        }
    }
}
