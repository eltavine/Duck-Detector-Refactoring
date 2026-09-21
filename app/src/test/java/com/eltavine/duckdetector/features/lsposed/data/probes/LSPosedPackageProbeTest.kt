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

package com.eltavine.duckdetector.features.lsposed.data.probes

import com.eltavine.duckdetector.core.packagevisibility.InstalledApplicationRecord
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageInventory
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageInventoryResult
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility
import com.eltavine.duckdetector.core.packagevisibility.PackageInventoryFailure
import com.eltavine.duckdetector.core.packagevisibility.PackageInventoryFailureKind
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedPackageVisibility
import org.junit.Assert.assertEquals
import org.junit.Test

class LSPosedPackageProbeTest {

    private val probe = LSPosedPackageProbe()

    @Test
    fun `unavailable inventory remains unknown and does not invent absence evidence`() {
        val result = probe.evaluate(
            InstalledPackageInventoryResult.Unavailable(
                PackageInventoryFailure(
                    kind = PackageInventoryFailureKind.PLATFORM_QUERY_FAILED,
                    detail = "binder failure",
                ),
            ),
        )

        assertEquals(LSPosedPackageVisibility.UNKNOWN, result.packageVisibility)
        assertEquals(0, result.managerPackageCount)
        assertEquals(0, result.moduleAppCount)
        assertEquals(emptyList<Any>(), result.signals)
    }

    @Test
    fun `platform-neutral application records drive manager and module signals`() {
        val result = probe.evaluate(
            InstalledPackageInventoryResult.Available(
                InstalledPackageInventory(
                    applications = listOf(
                        InstalledApplicationRecord(
                            packageName = "org.lsposed.manager",
                            label = "LSPosed",
                            metadataKeys = setOf("xposedmodule", "xposedminversion"),
                        ),
                    ),
                    visibility = InstalledPackageVisibility.FULL,
                    suspiciouslyLowInventory = true,
                ),
            ),
        )

        assertEquals(LSPosedPackageVisibility.FULL, result.packageVisibility)
        assertEquals(1, result.managerPackageCount)
        assertEquals(1, result.moduleAppCount)
        assertEquals(2, result.signals.size)
        assertEquals("LSPosed", result.signals.last().label)
    }
}
