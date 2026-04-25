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
}
