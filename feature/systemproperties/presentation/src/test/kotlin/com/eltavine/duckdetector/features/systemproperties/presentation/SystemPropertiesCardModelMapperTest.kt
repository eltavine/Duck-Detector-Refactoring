/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySignal
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySource
import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.features.systemproperties.domain.PropertyAreaClocks
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodOutcome
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodResult
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesReport
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesStage
import com.eltavine.duckdetector.features.systemproperties.presentation.model.SystemPropertiesHeaderFact
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SystemPropertiesCardModelMapperTest {

    private val mapper = SystemPropertiesCardModelMapper()

    @Test
    fun `prop area method and scan rows are rendered`() {
        val report = SystemPropertiesReport(
            stage = SystemPropertiesStage.READY,
            propertySignals = emptyList(),
            propAreaSignals = listOf(
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
            methods = listOf(
                SystemPropertiesMethodResult(
                    label = "Prop area layout",
                    summary = "2 hole(s)",
                    outcome = SystemPropertiesMethodOutcome.DANGER,
                    detail = "Raw /dev/__properties__ layout scan across 6 area(s).",
                ),
            ),
        )

        val model = mapper.map(report)

        assertFalse(model.subtitle.contains("ro-serial anomaly", ignoreCase = true))
        assertFalse(model.methodRows.any { it.label == "RO property handles" })
        assertFalse(model.consistencyRows.any { it.label.contains("ro serial anomaly:") })
        assertFalse(model.scanRows.any { it.label == "RO handles checked" })
        assertFalse(model.scanRows.any { it.label == "RO serial anomalies" })
        assertTrue(model.subtitle.contains("prop-area hole", ignoreCase = true))
        assertTrue(model.methodRows.any { it.label == "Prop area layout" && it.value == "2 hole(s)" })
        assertTrue(model.consistencyRows.any { it.label.contains("prop_area hole:") })
        assertEquals("6", model.scanRows.single { it.label == "Prop areas scanned" }.value)
        assertEquals("2", model.scanRows.single { it.label == "Prop area holes" }.value)
    }

    @Test
    fun `unavailable prop area keeps ready report at support`() {
        val report = SystemPropertiesReport(
            stage = SystemPropertiesStage.READY,
            propertySignals = emptyList(),
            propAreaSignals = emptyList(),
            infoSignals = emptyList(),
            checkedRuleCount = 12,
            observedRuleCount = 1,
            infoPropertyCount = 0,
            reflectionHitCount = 1,
            getpropHitCount = 1,
            jvmHitCount = 0,
            nativeHitCount = 1,
            bootParamHitCount = 1,
            buildSignalCount = 1,
            propAreaAvailable = false,
            propAreaContextCount = 0,
            propAreaHoleCount = 0,
            methods = listOf(
                SystemPropertiesMethodResult(
                    label = "Prop area layout",
                    summary = "Unavailable",
                    outcome = SystemPropertiesMethodOutcome.SUPPORT,
                    detail = "Property area scan unavailable.",
                ),
            ),
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertTrue(model.verdict.contains("reduced coverage", ignoreCase = true))
    }

    @Test
    fun `a property area clock gap is a warning on the row and the card`() {
        val nanos = 1_778_300_194_915_999_998L
        val model = mapper.map(clockReport(PropertyAreaClocks.Ordered(nanos)))
        val row = model.consistencyRows.single()
        val review = model.headerFacts.single { it.fact == SystemPropertiesHeaderFact.REVIEW }

        assertEquals(DetectionSeverity.WARNING, model.status.severity)
        assertEquals("1 property signal(s) need review", model.verdict)
        assertEquals("1", review.value)
        assertEquals(DetectionSeverity.WARNING, row.status.severity)
        assertEquals("Device property-area anomaly", row.label)
        assertEquals(nanos.toString(), row.value)
        assertTrue(model.impactItems.any { it.status.severity == DetectionSeverity.WARNING })
    }

    @Test
    fun `property area clocks out of that order show clean`() {
        val model = mapper.map(clockReport(PropertyAreaClocks.NotOrdered))
        val row = model.consistencyRows.single()

        assertEquals(DetectionSeverity.ALL_CLEAR, model.status.severity)
        assertEquals("Device property-area anomaly", row.label)
        assertEquals("Clean", row.value)
        assertEquals(DetectionSeverity.ALL_CLEAR, row.status.severity)
    }

    @Test
    fun `unreadable property area clocks show unavailable rather than clean`() {
        val row = mapper.map(clockReport(PropertyAreaClocks.Unreadable)).consistencyRows.single()

        assertEquals("Device property-area anomaly", row.label)
        assertEquals("Unavailable", row.value)
        assertEquals(DetectionSeverity.INFO, row.status.severity)
    }

    private fun clockReport(clocks: PropertyAreaClocks) = SystemPropertiesReport(
        stage = SystemPropertiesStage.READY,
        propertySignals = emptyList(),
        propAreaSignals = emptyList(),
        infoSignals = emptyList(),
        checkedRuleCount = 1,
        observedRuleCount = 1,
        infoPropertyCount = 0,
        reflectionHitCount = 1,
        getpropHitCount = 1,
        jvmHitCount = 0,
        nativeHitCount = 1,
        bootParamHitCount = 0,
        buildSignalCount = 0,
        propAreaAvailable = true,
        propAreaContextCount = 3,
        propAreaHoleCount = 0,
        methods = emptyList(),
        propertyAreaClocks = clocks,
    )
}
