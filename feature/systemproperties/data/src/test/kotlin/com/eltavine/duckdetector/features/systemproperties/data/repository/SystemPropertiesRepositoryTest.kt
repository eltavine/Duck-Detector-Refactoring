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

package com.eltavine.duckdetector.features.systemproperties.data.repository

import com.eltavine.duckdetector.capability.systemproperties.domain.PropAreaFinding
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertiesNativeSnapshot
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySource
import com.eltavine.duckdetector.capability.systemproperties.domain.MultiSourcePropertyRead
import com.eltavine.duckdetector.features.systemproperties.data.rules.SystemPropertiesCatalog
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SystemPropertiesRepositoryTest {

    private val repository = SystemPropertiesRepository()

    @Test
    fun `OEM unlock capability remains informational while an unlocked bootloader is dangerous`() {
        for (property in listOf("sys.oem_unlock_allowed", "ro.oem_unlock_supported")) {
            val rule = SystemPropertiesCatalog.rules.single { it.property == property }
            for (value in listOf("0", "1", "false", "true", "unexpected")) {
                val read = MultiSourcePropertyRead(
                    property = property,
                    category = rule.category,
                    preferredValue = value,
                    preferredSource = SystemPropertySource.GETPROP,
                    sourceValues = mapOf(SystemPropertySource.GETPROP to value),
                )
                assertEquals(SystemPropertySeverity.NEUTRAL, repository.buildRuleSignal(rule, read).severity)
            }
        }

        val unlockedRule = SystemPropertiesCatalog.rules.single { it.property == "ro.boot.flash.locked" }
        val unlockedRead = MultiSourcePropertyRead(
            property = unlockedRule.property,
            category = unlockedRule.category,
            preferredValue = "0",
            preferredSource = SystemPropertySource.GETPROP,
            sourceValues = mapOf(SystemPropertySource.GETPROP to "0"),
        )
        assertEquals(SystemPropertySeverity.DANGER, repository.buildRuleSignal(unlockedRule, unlockedRead).severity)
    }

    @Test
    fun `adbd config prop hole maps to danger`() {
        val snapshot = SystemPropertiesNativeSnapshot(
            propAreaAvailable = true,
            propAreaContextCount = 3,
            propAreaHoleCount = 2,
            propAreaFindings = listOf(
                PropAreaFinding(
                    context = "u:object_r:adbd_config_prop:s0",
                    holeCount = 2,
                    detail = "Found hole in prop area: u:object_r:adbd_config_prop:s0",
                ),
            ),
        )

        val signals = repository.buildPropAreaSignals(snapshot)
        val method = buildPropAreaMethod(
            propAreaAvailable = snapshot.propAreaAvailable,
            propAreaContextCount = snapshot.propAreaContextCount,
            propAreaHoleCount = snapshot.propAreaHoleCount,
            propAreaSignals = signals,
        )

        assertEquals(1, signals.size)
        assertEquals(SystemPropertySeverity.DANGER, signals.single().severity)
        assertTrue(signals.single().property.contains("adbd_config_prop"))
        assertEquals("2 hole(s)", method.summary)
        assertEquals(SystemPropertiesMethodOutcome.DANGER, method.outcome)
    }

    @Test
    fun `regular prop area hole maps to warning`() {
        val snapshot = SystemPropertiesNativeSnapshot(
            propAreaAvailable = true,
            propAreaContextCount = 5,
            propAreaHoleCount = 1,
            propAreaFindings = listOf(
                PropAreaFinding(
                    context = "u:object_r:vendor_prop:s0",
                    holeCount = 1,
                    detail = "Found hole in prop area: u:object_r:vendor_prop:s0",
                ),
            ),
        )

        val signals = repository.buildPropAreaSignals(snapshot)
        val method = buildPropAreaMethod(
            propAreaAvailable = snapshot.propAreaAvailable,
            propAreaContextCount = snapshot.propAreaContextCount,
            propAreaHoleCount = snapshot.propAreaHoleCount,
            propAreaSignals = signals,
        )

        assertEquals(SystemPropertySeverity.WARNING, signals.single().severity)
        assertEquals(SystemPropertiesMethodOutcome.WARNING, method.outcome)
    }

    @Test
    fun `unavailable prop area scan yields support without findings`() {
        val snapshot = SystemPropertiesNativeSnapshot()

        val signals = repository.buildPropAreaSignals(snapshot)
        val method = buildPropAreaMethod(
            propAreaAvailable = snapshot.propAreaAvailable,
            propAreaContextCount = snapshot.propAreaContextCount,
            propAreaHoleCount = snapshot.propAreaHoleCount,
            propAreaSignals = signals,
        )

        assertTrue(signals.isEmpty())
        assertEquals("Unavailable", method.summary)
        assertEquals(SystemPropertiesMethodOutcome.SUPPORT, method.outcome)
    }
}
