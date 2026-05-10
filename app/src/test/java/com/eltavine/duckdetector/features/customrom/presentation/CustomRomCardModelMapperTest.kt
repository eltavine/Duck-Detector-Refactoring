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

package com.eltavine.duckdetector.features.customrom.presentation

import com.eltavine.duckdetector.features.customrom.domain.CustomRomFinding
import com.eltavine.duckdetector.features.customrom.domain.CustomRomModificationFinding
import com.eltavine.duckdetector.features.customrom.domain.CustomRomMethodOutcome
import com.eltavine.duckdetector.features.customrom.domain.CustomRomMethodResult
import com.eltavine.duckdetector.features.customrom.domain.CustomRomPackageVisibility
import com.eltavine.duckdetector.features.customrom.domain.CustomRomReport
import com.eltavine.duckdetector.features.customrom.domain.CustomRomStage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CustomRomCardModelMapperTest {

    private val mapper = CustomRomCardModelMapper()

    @Test
    fun `modification and symbol signals are surfaced in card rows`() {
        val report = readyReport(
            propertyAreaAvailable = true,
            modificationFindings = listOf(
                CustomRomModificationFinding(
                    category = "Prop area",
                    signal = "u:object_r:shell_prop:s0",
                    summary = "Abnormal prop area",
                    detail = "mode=644 uid=0 gid=0",
                ),
            ),
            symbolFindings = listOf(
                CustomRomFinding(
                    romName = "Native symbol trace",
                    signal = "ANetworkSession::threadLoopEv",
                    detail = "/apex/com.android.media/lib64/libstagefright.so",
                ),
            ),
        )

        val model = mapper.map(report)

        assertEquals(
            "1 modification signal(s) + 1 native symbol trace(s) detected",
            model.verdict,
        )
        assertTrue(
            model.buildRows.any {
                it.label == "u:object_r:shell_prop:s0" &&
                    it.value == "Abnormal prop area" &&
                    it.detail?.contains("Prop area") == true
            },
        )
        assertTrue(
            model.frameworkRows.any {
                it.label == "ANetworkSession::threadLoopEv" &&
                    it.value == "Native symbol trace"
            },
        )
        assertTrue(
            model.scanRows.any {
                it.label == "Modification props checked" &&
                    it.value == "18"
            },
        )
        assertTrue(
            model.scanRows.any {
                it.label == "Prop area contexts" &&
                    it.value == "4"
            },
        )
        assertTrue(
            model.scanRows.any {
                it.label == "Prop area anomalies" &&
                    it.value == "1"
            },
        )
        assertTrue(
            model.scanRows.any {
                it.label == "Prop item anomalies" &&
                    it.value == "2"
            },
        )
    }

    @Test
    fun `missing property area coverage is not shown as clean`() {
        val report = readyReport(
            propertyAreaAvailable = false,
        )

        val model = mapper.map(report)

        assertTrue(
            model.buildRows.any {
                it.label == "Modification" &&
                    it.value == "Unavailable" &&
                    it.detail?.contains("property-area coverage was unavailable") == true
            },
        )
        assertTrue(
            model.summary.contains("incomplete on this build"),
        )
    }

    @Test
    fun `missing native coverage is surfaced as unavailable rather than clean`() {
        val report = readyReport(
            nativeAvailable = false,
        )

        val model = mapper.map(report)

        assertTrue(
            model.summary.contains("Native coverage was unavailable on this build"),
        )
        assertTrue(
            model.impactItems.any {
                it.text.contains("Native coverage was unavailable on this build")
            },
        )
        assertTrue(
            model.frameworkRows.any {
                it.label == "Resource maps" &&
                    it.value == "Unavailable"
            },
        )
    }

    @Test
    fun `unsupported native symbol scan is not shown as clean`() {
        val report = readyReport(
            symbolScanAvailable = false,
        )

        val model = mapper.map(report)

        assertTrue(
            model.frameworkRows.any {
                it.label == "Native symbols" &&
                    it.value == "Unsupported" &&
                    it.detail?.contains("Android 10+") == true
            },
        )
        assertTrue(
            model.verdict == "Custom ROM scan has reduced coverage",
        )
    }

    private fun readyReport(
        nativeAvailable: Boolean = true,
        propertyAreaAvailable: Boolean = true,
        symbolScanAvailable: Boolean = true,
        propertyAreaContextCount: Int = 4,
        propertyAreaAnomalyCount: Int = 1,
        propertyAreaItemAnomalyCount: Int = 2,
        modificationFindings: List<CustomRomModificationFinding> = emptyList(),
        symbolFindings: List<CustomRomFinding> = emptyList(),
    ): CustomRomReport {
        return CustomRomReport(
            stage = CustomRomStage.READY,
            packageVisibility = CustomRomPackageVisibility.FULL,
            detectedRoms = emptyList(),
            propertyFindings = emptyList(),
            buildFindings = emptyList(),
            modificationFindings = modificationFindings,
            packageFindings = emptyList(),
            serviceFindings = emptyList(),
            reflectionFindings = emptyList(),
            platformFileFindings = emptyList(),
            resourceInjectionFindings = emptyList(),
            recoveryScripts = emptyList(),
            policyFindings = emptyList(),
            overlayFindings = emptyList(),
            symbolFindings = symbolFindings,
            nativeAvailable = nativeAvailable,
            propertyAreaAvailable = propertyAreaAvailable,
            symbolScanAvailable = symbolScanAvailable,
            checkedPropertyCount = 10,
            checkedBuildFieldCount = 3,
            checkedModificationPropertyCount = 18,
            checkedPackageCount = 0,
            checkedServiceCount = 0,
            listedServiceCount = 0,
            methods = listOf(
                CustomRomMethodResult("propertyScan", "Clean", CustomRomMethodOutcome.CLEAN),
                CustomRomMethodResult("buildFieldScan", "Clean", CustomRomMethodOutcome.CLEAN),
                CustomRomMethodResult("modificationScan", "Clean", CustomRomMethodOutcome.CLEAN),
                CustomRomMethodResult("packageScan", "Clean", CustomRomMethodOutcome.CLEAN),
                CustomRomMethodResult("serviceScan", "Clean", CustomRomMethodOutcome.CLEAN),
                CustomRomMethodResult("reflectionScan", "Clean", CustomRomMethodOutcome.CLEAN),
                if (nativeAvailable) {
                    CustomRomMethodResult("mapsInjection", "Clean", CustomRomMethodOutcome.CLEAN)
                } else {
                    CustomRomMethodResult(
                        "mapsInjection",
                        "Unavailable",
                        CustomRomMethodOutcome.SUPPORT,
                    )
                },
                if (nativeAvailable) {
                    CustomRomMethodResult("nativeFiles", "Clean", CustomRomMethodOutcome.CLEAN)
                } else {
                    CustomRomMethodResult(
                        "nativeFiles",
                        "Unavailable",
                        CustomRomMethodOutcome.SUPPORT,
                    )
                },
                if (nativeAvailable) {
                    CustomRomMethodResult("nativePolicy", "Clean", CustomRomMethodOutcome.CLEAN)
                } else {
                    CustomRomMethodResult(
                        "nativePolicy",
                        "Unavailable",
                        CustomRomMethodOutcome.SUPPORT,
                    )
                },
                if (!nativeAvailable) {
                    CustomRomMethodResult(
                        "nativeSymbols",
                        "Unavailable",
                        CustomRomMethodOutcome.SUPPORT,
                    )
                } else if (symbolScanAvailable) {
                    CustomRomMethodResult("nativeSymbols", "Clean", CustomRomMethodOutcome.CLEAN)
                } else {
                    CustomRomMethodResult(
                        "nativeSymbols",
                        "Unsupported",
                        CustomRomMethodOutcome.SUPPORT,
                    )
                },
                if (nativeAvailable) {
                    CustomRomMethodResult("nativeLibrary", "Loaded", CustomRomMethodOutcome.CLEAN)
                } else {
                    CustomRomMethodResult(
                        "nativeLibrary",
                        "Unavailable",
                        CustomRomMethodOutcome.SUPPORT,
                    )
                },
            ),
            propertyAreaContextCount = propertyAreaContextCount,
            propertyAreaAnomalyCount = propertyAreaAnomalyCount,
            propertyAreaItemAnomalyCount = propertyAreaItemAnomalyCount,
        )
    }
}
