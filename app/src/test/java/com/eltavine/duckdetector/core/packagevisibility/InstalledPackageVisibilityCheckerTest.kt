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

package com.eltavine.duckdetector.core.packagevisibility

import android.os.Build
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InstalledPackageVisibilityCheckerTest {

    @Test
    fun `full inventory below sixty is suspicious on android r and newer`() {
        assertTrue(
            InstalledPackageVisibilityChecker.hasSuspiciouslyLowInventory(
                visibility = InstalledPackageVisibility.FULL,
                installedPackageCount = 43,
                sdkInt = Build.VERSION_CODES.R,
            ),
        )
    }

    @Test
    fun `restricted inventory or pre-r does not trigger low-count warning`() {
        assertFalse(
            InstalledPackageVisibilityChecker.hasSuspiciouslyLowInventory(
                visibility = InstalledPackageVisibility.RESTRICTED,
                installedPackageCount = 43,
                sdkInt = Build.VERSION_CODES.UPSIDE_DOWN_CAKE,
            ),
        )
        assertFalse(
            InstalledPackageVisibilityChecker.hasSuspiciouslyLowInventory(
                visibility = InstalledPackageVisibility.FULL,
                installedPackageCount = 43,
                sdkInt = Build.VERSION_CODES.Q,
            ),
        )
    }

    @Test
    fun `an inventory that produced nothing is unknown rather than full visibility`() {
        assertEquals(
            InstalledPackageVisibility.UNKNOWN,
            InstalledPackageVisibilityChecker.resolveVisibility(
                inventoryHasCaller = false,
                environment = environment(
                    deviceSdk = Build.VERSION_CODES.Q,
                    targetSdk = Build.VERSION_CODES.Q,
                    queryAllPackagesRequested = false,
                ),
            ),
        )
    }

    @Test
    fun `a compatibility-exempt caller has full visibility without requesting the permission`() {
        assertEquals(
            InstalledPackageVisibility.FULL,
            InstalledPackageVisibilityChecker.resolveVisibility(
                inventoryHasCaller = true,
                environment = environment(
                    deviceSdk = Build.VERSION_CODES.UPSIDE_DOWN_CAKE,
                    targetSdk = Build.VERSION_CODES.Q,
                    queryAllPackagesRequested = false,
                ),
            ),
        )
    }

    @Test
    fun `a filtered caller requesting the broad permission has full visibility`() {
        assertEquals(
            InstalledPackageVisibility.FULL,
            InstalledPackageVisibilityChecker.resolveVisibility(
                inventoryHasCaller = true,
                environment = environment(queryAllPackagesRequested = true),
            ),
        )
    }

    @Test
    fun `a filtered caller without the permission stays restricted however many packages returned`() {
        // The count no longer decides this. A filtered caller still sees itself plus everything
        // visible to every app, so a list longer than the old ten-package threshold said nothing
        // about whether the platform was withholding the packages actually being looked for.
        assertEquals(
            InstalledPackageVisibility.RESTRICTED,
            InstalledPackageVisibilityChecker.resolveVisibility(
                inventoryHasCaller = true,
                environment = environment(queryAllPackagesRequested = false),
            ),
        )
    }

    @Test
    fun `query failure stays unavailable instead of becoming an empty inventory`() {
        val failure = PackageInventoryFailure(
            kind = PackageInventoryFailureKind.PLATFORM_QUERY_FAILED,
            detail = "SecurityException",
        )
        val reader = DefaultInstalledPackageInventoryReader(
            callerPackageName = CALLER_PACKAGE,
            applicationsSource = InstalledApplicationsSource {
                InstalledApplicationsQueryResult.Unavailable(failure)
            },
            environmentProvider = PackageVisibilityEnvironmentProvider { environment() },
        )

        assertEquals(
            InstalledPackageInventoryResult.Unavailable(failure),
            reader.read(),
        )
    }

    @Test
    fun `visibility environment failure stays explicit`() {
        val reader = DefaultInstalledPackageInventoryReader(
            callerPackageName = CALLER_PACKAGE,
            applicationsSource = InstalledApplicationsSource {
                InstalledApplicationsQueryResult.Available(
                    listOf(
                        InstalledApplicationRecord(
                            packageName = CALLER_PACKAGE,
                            label = CALLER_PACKAGE,
                            metadataKeys = emptySet(),
                        ),
                    ),
                )
            },
            environmentProvider = PackageVisibilityEnvironmentProvider {
                throw SecurityException("environment blocked")
            },
        )

        val result = reader.read() as InstalledPackageInventoryResult.Unavailable

        assertEquals(PackageInventoryFailureKind.VISIBILITY_ENVIRONMENT_FAILED, result.failure.kind)
        assertTrue(result.failure.detail.contains("SecurityException"))
    }

    @Test
    fun `reader derives names visibility and low-inventory warning in one snapshot`() {
        val reader = DefaultInstalledPackageInventoryReader(
            callerPackageName = CALLER_PACKAGE,
            applicationsSource = InstalledApplicationsSource {
                InstalledApplicationsQueryResult.Available(
                    listOf(
                        InstalledApplicationRecord(
                            packageName = CALLER_PACKAGE,
                            label = "Duck Detector",
                            metadataKeys = emptySet(),
                        ),
                    ),
                )
            },
            environmentProvider = PackageVisibilityEnvironmentProvider {
                environment(queryAllPackagesRequested = true)
            },
        )

        val result = reader.read() as InstalledPackageInventoryResult.Available

        assertEquals(setOf(CALLER_PACKAGE), result.inventory.packageNames)
        assertEquals(InstalledPackageVisibility.FULL, result.inventory.visibility)
        assertTrue(result.inventory.suspiciouslyLowInventory)
    }

    private fun environment(
        deviceSdk: Int = Build.VERSION_CODES.UPSIDE_DOWN_CAKE,
        targetSdk: Int = Build.VERSION_CODES.UPSIDE_DOWN_CAKE,
        queryAllPackagesRequested: Boolean = false,
    ): PackageVisibilityEnvironment {
        return PackageVisibilityEnvironment(
            deviceSdk = deviceSdk,
            targetSdk = targetSdk,
            queryAllPackagesRequested = queryAllPackagesRequested,
        )
    }

    private companion object {
        const val CALLER_PACKAGE = "com.eltavine.duckdetector"
    }
}
