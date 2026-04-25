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

package com.eltavine.duckdetector.features.dangerousapps.data.repository

import android.content.Context
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibilityChecker
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility

object PackageVisibilityChecker {

    fun detect(
        context: Context,
        installedPackageCount: Int,
    ): DangerousPackageVisibility {
        return when (InstalledPackageVisibilityChecker.detect(context, installedPackageCount)) {
            InstalledPackageVisibility.FULL -> DangerousPackageVisibility.FULL
            InstalledPackageVisibility.RESTRICTED -> DangerousPackageVisibility.RESTRICTED
            InstalledPackageVisibility.UNKNOWN -> DangerousPackageVisibility.UNKNOWN
        }
    }

    fun getInstalledPackages(context: Context): Set<String> {
        return InstalledPackageVisibilityChecker.getInstalledPackages(context)
    }

    fun hasSuspiciouslyLowInventory(
        packageVisibility: DangerousPackageVisibility,
        installedPackageCount: Int,
    ): Boolean {
        val visibility = when (packageVisibility) {
            DangerousPackageVisibility.FULL -> InstalledPackageVisibility.FULL
            DangerousPackageVisibility.RESTRICTED -> InstalledPackageVisibility.RESTRICTED
            DangerousPackageVisibility.UNKNOWN -> InstalledPackageVisibility.UNKNOWN
        }
        return InstalledPackageVisibilityChecker.hasSuspiciouslyLowInventory(
            visibility = visibility,
            installedPackageCount = installedPackageCount,
        )
    }
}
