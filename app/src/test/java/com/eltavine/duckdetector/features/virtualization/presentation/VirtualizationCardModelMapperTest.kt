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

package com.eltavine.duckdetector.features.virtualization.presentation

import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility
import com.eltavine.duckdetector.core.ui.model.DetectionSeverity
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationImpact
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationMethodOutcome
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationMethodResult
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationReport
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignal
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalGroup
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationStage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VirtualizationCardModelMapperTest {

    private val mapper = VirtualizationCardModelMapper()

    @Test
    fun `host app only report stays info and keeps host section`() {
        val model = mapper.map(
            VirtualizationReport(
                stage = VirtualizationStage.READY,
                nativeAvailable = true,
                startupPreloadAvailable = false,
                startupPreloadContextValid = false,
                crossProcessAvailable = false,
                isolatedProcessAvailable = false,
                asmSupported = false,
                eglAvailable = false,
                packageVisibility = InstalledPackageVisibility.FULL,
                dexPathEntryCount = 0,
                dexPathHitCount = 0,
                uidIdentityHitCount = 0,
                environmentHitCount = 0,
                translationHitCount = 0,
                runtimeArtifactHitCount = 0,
                consistencyHitCount = 0,
                isolatedConsistencyHitCount = 0,
                mountAnchorDriftCount = 0,
                mountNamespaceAvailable = false,
                honeypotHitCount = 0,
                syscallPackSupported = false,
                syscallPackHitCount = 0,
                hostAppCorroborationCount = 1,
                mapLineCount = 0,
                fdCount = 0,
                mountInfoCount = 0,
                signals = listOf(
                    VirtualizationSignal(
                        id = "host",
                        label = "VMOS Pro",
                        value = "Corroboration",
                        group = VirtualizationSignalGroup.HOST_APPS,
                        severity = VirtualizationSignalSeverity.INFO,
                        detail = "PackageManager",
                    ),
                ),
                methods = listOf(
                    VirtualizationMethodResult(
                        "Host apps",
                        "1 corroborating app(s)",
                        VirtualizationMethodOutcome.INFO
                    ),
                ),
                impacts = listOf(
                    VirtualizationImpact("Known host app", VirtualizationSignalSeverity.INFO),
                ),
            ),
        )

        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertTrue(model.summary.contains("host apps", ignoreCase = true))
        assertTrue(model.hostAppRows.any { it.label == "VMOS Pro" })
    }

    @Test
    fun `scan rows and method rows include startup preload and honeypots`() {
        val model = mapper.map(VirtualizationReport.loading())

        assertTrue(model.methodRows.any { it.label == "Startup preload" })
        assertTrue(model.methodRows.any { it.label == "Graphics renderer" })
        assertTrue(model.methodRows.any { it.label == "Isolated-process consistency" })
        assertTrue(model.methodRows.any { it.label == "ASM honeypots" })
        assertTrue(model.methodRows.any { it.label == "Sacrificial syscall pack" })
        assertTrue(model.scanRows.any { it.label == "Startup preload" })
        assertTrue(model.scanRows.any { it.label == "EGL renderer" })
        assertTrue(model.scanRows.any { it.label == "Isolated helper" })
        assertTrue(model.scanRows.any { it.label == "Honeypot hits" })
        assertTrue(model.scanRows.any { it.label == "Syscall pack" })
    }
}
