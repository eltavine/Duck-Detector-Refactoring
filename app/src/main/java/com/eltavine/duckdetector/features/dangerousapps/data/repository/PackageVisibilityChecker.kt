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
import com.eltavine.duckdetector.core.packagevisibility.AndroidInstalledPackageInventoryReader
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageInventoryReader
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageInventoryResult
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibilityChecker
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility

data class DangerousPackageInventory(
    val packageNames: Set<String>,
    val visibility: DangerousPackageVisibility,
    val suspiciouslyLow: Boolean,
    val issue: String? = null,
)

object PackageVisibilityChecker {

    fun inspect(
        reader: InstalledPackageInventoryReader,
    ): DangerousPackageInventory {
        return when (val result = reader.read()) {
            is InstalledPackageInventoryResult.Available -> {
                val inventory = result.inventory
                DangerousPackageInventory(
                    packageNames = inventory.packageNames,
                    visibility = inventory.visibility.toDangerousVisibility(),
                    suspiciouslyLow = inventory.suspiciouslyLowInventory,
                    issue = if (inventory.visibility == InstalledPackageVisibility.UNKNOWN) {
                        "PackageManager inventory did not include this app, so package absence is inconclusive."
                    } else {
                        null
                    },
                )
            }

            is InstalledPackageInventoryResult.Unavailable -> {
                DangerousPackageInventory(
                    packageNames = emptySet(),
                    visibility = DangerousPackageVisibility.UNKNOWN,
                    suspiciouslyLow = false,
                    issue = "PackageManager inventory unavailable: ${result.failure.detail}",
                )
            }
        }
    }

    fun inspect(context: Context): DangerousPackageInventory {
        return inspect(AndroidInstalledPackageInventoryReader(context.applicationContext))
    }

    @Deprecated("Use inspect() so query failure remains explicit.")
    @Suppress("DEPRECATION")
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

    @Deprecated("Use inspect() so query failure remains explicit.")
    @Suppress("DEPRECATION")
    fun getInstalledPackages(context: Context): Set<String> {
        return InstalledPackageVisibilityChecker.getInstalledPackages(context)
    }

    @Deprecated("Use inspect() so visibility and inventory are evaluated together.")
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

    private fun InstalledPackageVisibility.toDangerousVisibility(): DangerousPackageVisibility {
        return when (this) {
            InstalledPackageVisibility.FULL -> DangerousPackageVisibility.FULL
            InstalledPackageVisibility.RESTRICTED -> DangerousPackageVisibility.RESTRICTED
            InstalledPackageVisibility.UNKNOWN -> DangerousPackageVisibility.UNKNOWN
        }
    }
}
