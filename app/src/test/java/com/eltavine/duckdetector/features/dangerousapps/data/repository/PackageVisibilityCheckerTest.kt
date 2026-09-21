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

import com.eltavine.duckdetector.core.packagevisibility.InstalledApplicationRecord
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageInventory
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageInventoryReader
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageInventoryResult
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility
import com.eltavine.duckdetector.core.packagevisibility.PackageInventoryFailure
import com.eltavine.duckdetector.core.packagevisibility.PackageInventoryFailureKind
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Test

class PackageVisibilityCheckerTest {

    @Test
    fun `query failure maps to an explicit unknown feature result`() {
        val inventory = PackageVisibilityChecker.inspect(
            InstalledPackageInventoryReader {
                InstalledPackageInventoryResult.Unavailable(
                    PackageInventoryFailure(
                        kind = PackageInventoryFailureKind.PLATFORM_QUERY_FAILED,
                        detail = "SecurityException",
                    ),
                )
            },
        )

        assertEquals(DangerousPackageVisibility.UNKNOWN, inventory.visibility)
        assertEquals(emptySet<String>(), inventory.packageNames)
        assertFalse(inventory.suspiciouslyLow)
        assertNotNull(inventory.issue)
    }

    @Test
    fun `available inventory keeps the shared assessment and package set`() {
        val inventory = PackageVisibilityChecker.inspect(
            InstalledPackageInventoryReader {
                InstalledPackageInventoryResult.Available(
                    InstalledPackageInventory(
                        applications = listOf(
                            InstalledApplicationRecord(
                                packageName = "example.target",
                                label = "example.target",
                                metadataKeys = emptySet(),
                            ),
                        ),
                        visibility = InstalledPackageVisibility.RESTRICTED,
                        suspiciouslyLowInventory = false,
                    ),
                )
            },
        )

        assertEquals(DangerousPackageVisibility.RESTRICTED, inventory.visibility)
        assertEquals(setOf("example.target"), inventory.packageNames)
        assertFalse(inventory.suspiciouslyLow)
    }
}
