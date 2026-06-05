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

package com.eltavine.duckdetector.features.dangerousapps.presentation

import com.eltavine.duckdetector.core.ui.model.DetectionSeverity
import com.eltavine.duckdetector.features.dangerousapps.data.rules.DangerousAppsCatalog
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppFinding
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsReport
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsStage
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousDetectionMethod
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousDetectionMethodKind
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DangerousAppsCardModelMapperTest {

    private val mapper = DangerousAppsCardModelMapper()

    @Test
    fun `suspiciously low pm inventory becomes warning and mentions hma whitelist`() {
        val model = mapper.map(
            DangerousAppsReport(
                stage = DangerousAppsStage.READY,
                packageVisibility = DangerousPackageVisibility.FULL,
                packageManagerVisibleCount = 43,
                suspiciousLowPmInventory = true,
                suspiciousSharedStorageDenied = false,
                targets = DangerousAppsCatalog.targets,
                findings = emptyList(),
                hiddenFromPackageManager = emptyList(),
                probesRan = emptyList(),
                issues = listOf(
                    "PackageManager returned only 43 visible packages despite a full inventory result. This can happen under HMA-style whitelist filtering.",
                ),
            ),
        )

        assertEquals(DetectionSeverity.WARNING, model.status.severity)
        assertEquals("Package inventory unusually small", model.verdict)
        assertTrue(model.summary.contains("HMA-style whitelist filtering"))
        assertTrue(model.subtitle.contains("43 visible"))
        assertTrue(
            model.headerFacts.any { fact ->
                fact.label == "PM" &&
                        fact.status.severity == DetectionSeverity.WARNING &&
                        fact.value.contains("43")
            },
        )
    }

    @Test
    fun `hidden package copy uses direct corroboration language`() {
        val target = DangerousAppsCatalog.targets.first()
        val finding = DangerousAppFinding(
            target = target,
            methods = listOf(
                DangerousDetectionMethod(DangerousDetectionMethodKind.CREATE_PACKAGE_CONTEXT_ZIP),
            ),
        )
        val model = mapper.map(
            DangerousAppsReport(
                stage = DangerousAppsStage.READY,
                packageVisibility = DangerousPackageVisibility.FULL,
                packageManagerVisibleCount = 120,
                suspiciousLowPmInventory = false,
                suspiciousSharedStorageDenied = false,
                targets = DangerousAppsCatalog.targets,
                findings = listOf(finding),
                hiddenFromPackageManager = listOf(finding),
                probesRan = listOf(DangerousDetectionMethodKind.CREATE_PACKAGE_CONTEXT_ZIP),
            ),
        )

        assertEquals(DetectionSeverity.DANGER, model.status.severity)
        assertTrue(model.summary.contains("direct corroboration probes"))
        assertTrue(model.summary.contains("PackageManager inventory"))
        assertTrue(model.hmaAlert?.summary.orEmpty().contains("direct corroboration probes"))
        assertEquals(
            listOf("createPackageContext + ZipFile"),
            model.packageItems.single().methods,
        )
    }

    @Test
    fun `shared storage baseline denial becomes warning and mentions shared user gid`() {
        val model = mapper.map(
            DangerousAppsReport(
                stage = DangerousAppsStage.READY,
                packageVisibility = DangerousPackageVisibility.FULL,
                packageManagerVisibleCount = 120,
                suspiciousLowPmInventory = false,
                suspiciousSharedStorageDenied = true,
                targets = DangerousAppsCatalog.targets,
                findings = emptyList(),
                hiddenFromPackageManager = emptyList(),
                probesRan = emptyList(),
                issues = listOf(
                    "Shared external-storage baseline paths all returned EACCES/EPERM. This suggests shared user gid or related zygote storage groups may have been restricted.",
                ),
            ),
        )

        assertEquals(DetectionSeverity.WARNING, model.status.severity)
        assertEquals("Shared storage baseline denied", model.verdict)
        assertTrue(model.summary.contains("shared user gid"))
    }
}
