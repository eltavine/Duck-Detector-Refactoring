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
import com.eltavine.duckdetector.features.systemproperties.domain.PropertyAreaMtime
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
    fun `property area mtimes stay an unscored method row whatever their order`() {
        // System newer than debug, and debug newer than a radio area stamped before the clock was set.
        val model = mapper.map(
            mtimeReport(
                PropertyAreaMtime.Recorded(DEBUG, epochSeconds = 1_791_504_000L, nanoseconds = 5L),
                PropertyAreaMtime.Recorded(RADIO, epochSeconds = 13_132_800L, nanoseconds = 0L),
                PropertyAreaMtime.Recorded(SYSTEM, epochSeconds = 1_791_504_100L, nanoseconds = 0L),
            ),
        )
        val row = model.methodRows.single { it.label == "Prop area mtimes" }
        val review = model.headerFacts.single { it.fact == SystemPropertiesHeaderFact.REVIEW }

        assertEquals(DetectionSeverity.ALL_CLEAR, model.status.severity)
        assertEquals("No risky property or coherence drift", model.verdict)
        assertEquals("None", review.value)
        assertTrue(model.consistencyRows.isEmpty())
        assertEquals(DetectionSeverity.INFO, row.status.severity)
        assertEquals("3 recorded", row.value)
        assertTrue(row.detail.orEmpty().contains("$DEBUG: 2026-10-09T00:00:00.000000005Z"))
        assertTrue(row.detail.orEmpty().contains("$RADIO: 1970-06-02T00:00:00Z"))
        assertTrue(row.detail.orEmpty().contains("$SYSTEM: 2026-10-09T00:01:40Z"))
    }

    @Test
    fun `an unreadable property area keeps its errno and is not counted as recorded`() {
        val row = mapper.map(
            mtimeReport(
                PropertyAreaMtime.StatFailed(DEBUG, errno = "EACCES"),
                PropertyAreaMtime.NotRegularFile(RADIO),
                PropertyAreaMtime.Recorded(SYSTEM, epochSeconds = 0L, nanoseconds = 0L),
            ),
        ).methodRows.single { it.label == "Prop area mtimes" }

        assertEquals("1 of 3 recorded", row.value)
        assertEquals(DetectionSeverity.INFO, row.status.severity)
        assertTrue(row.detail.orEmpty().contains("$DEBUG: lstat failed: EACCES"))
        assertTrue(row.detail.orEmpty().contains("$RADIO: not a regular file"))
        assertTrue(row.detail.orEmpty().contains("$SYSTEM: 1970-01-01T00:00:00Z"))
    }

    @Test
    fun `no readable property area reads unavailable`() {
        val row = mapper.map(
            mtimeReport(
                PropertyAreaMtime.StatFailed(DEBUG, errno = "ENOENT"),
                PropertyAreaMtime.StatFailed(RADIO, errno = "EACCES"),
                PropertyAreaMtime.StatFailed(SYSTEM, errno = "ENOENT"),
            ),
        ).methodRows.single { it.label == "Prop area mtimes" }

        assertEquals("Unavailable", row.value)
        assertEquals(DetectionSeverity.INFO, row.status.severity)
    }

    @Test
    fun `an mtime beyond Instant's range is shown raw`() {
        val row = mapper.map(
            mtimeReport(PropertyAreaMtime.Recorded(DEBUG, epochSeconds = Long.MAX_VALUE, nanoseconds = 7L)),
        ).methodRows.single { it.label == "Prop area mtimes" }

        assertTrue(row.detail.orEmpty().contains("$DEBUG: ${Long.MAX_VALUE} s + 7 ns from the epoch"))
    }

    @Test
    fun `a report without property area mtimes adds no method row`() {
        assertTrue(mapper.map(mtimeReport()).methodRows.isEmpty())
    }

    private fun mtimeReport(vararg mtimes: PropertyAreaMtime) = SystemPropertiesReport(
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
        propertyAreaMtimes = mtimes.toList(),
    )

    private companion object {
        const val DEBUG = "u:object_r:debug_prop:s0"
        const val RADIO = "u:object_r:radio_prop:s0"
        const val SYSTEM = "u:object_r:system_prop:s0"
    }
}
