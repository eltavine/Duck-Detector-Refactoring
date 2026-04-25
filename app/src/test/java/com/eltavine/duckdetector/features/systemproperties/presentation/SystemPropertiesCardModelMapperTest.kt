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

package com.eltavine.duckdetector.features.systemproperties.presentation

import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodOutcome
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodResult
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesReport
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesStage
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySignal
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SystemPropertiesCardModelMapperTest {

    private val mapper = SystemPropertiesCardModelMapper()

    @Test
    fun `prop area method and scan rows are rendered`() {
        val report = SystemPropertiesReport(
            stage = SystemPropertiesStage.READY,
            signals = listOf(
                SystemPropertySignal(
                    property = "ro serial anomaly: ro.build.fingerprint",
                    description = "Read-only property serial anomaly",
                    value = "low24=0x000002",
                    category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
                    severity = SystemPropertySeverity.DANGER,
                    source = SystemPropertySource.NATIVE_LIBC,
                    detail = "Read-only property serial low24 was non-zero in 3/3 native libc sample(s).",
                ),
                SystemPropertySignal(
                    property = "prop_area hole: u:object_r:shell_prop:s0",
                    description = "Raw property area layout residue",
                    value = "2 hole(s)",
                    category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
                    severity = SystemPropertySeverity.DANGER,
                    source = SystemPropertySource.NATIVE_LIBC,
                    detail = "Found hole in prop area: u:object_r:shell_prop:s0",
                ),
            ),
            infoSignals = emptyList(),
            checkedRuleCount = 12,
            observedRuleCount = 4,
            infoPropertyCount = 0,
            reflectionHitCount = 4,
            getpropHitCount = 4,
            jvmHitCount = 0,
            nativeHitCount = 4,
            bootParamHitCount = 2,
            buildSignalCount = 1,
            propAreaAvailable = true,
            propAreaContextCount = 6,
            propAreaHoleCount = 2,
            readOnlySerialAvailable = true,
            readOnlySerialCheckedCount = 8,
            readOnlySerialFindingCount = 1,
            methods = listOf(
                SystemPropertiesMethodResult(
                    label = "Read-only serials",
                    summary = "1 anomaly(s)",
                    outcome = SystemPropertiesMethodOutcome.DANGER,
                    detail = "Sampled native libc serials for 8 tracked ro.* property/properties.",
                ),
                SystemPropertiesMethodResult(
                    label = "Prop area layout",
                    summary = "2 hole(s)",
                    outcome = SystemPropertiesMethodOutcome.DANGER,
                    detail = "Raw /dev/__properties__ layout scan across 6 area(s).",
                ),
            ),
        )

        val model = mapper.map(report)

        assertTrue(model.subtitle.contains("ro-serial anomaly", ignoreCase = true))
        assertTrue(model.methodRows.any { it.label == "Read-only serials" && it.value == "1 anomaly(s)" })
        assertTrue(model.consistencyRows.any { it.label.contains("ro serial anomaly:") })
        assertEquals("8", model.scanRows.single { it.label == "RO serial checks" }.value)
        assertEquals("1", model.scanRows.single { it.label == "RO serial anomalies" }.value)
        assertTrue(model.subtitle.contains("prop-area hole", ignoreCase = true))
        assertTrue(model.methodRows.any { it.label == "Prop area layout" && it.value == "2 hole(s)" })
        assertTrue(model.consistencyRows.any { it.label.contains("prop_area hole:") })
        assertEquals("6", model.scanRows.single { it.label == "Prop areas scanned" }.value)
        assertEquals("2", model.scanRows.single { it.label == "Prop area holes" }.value)
    }
}
