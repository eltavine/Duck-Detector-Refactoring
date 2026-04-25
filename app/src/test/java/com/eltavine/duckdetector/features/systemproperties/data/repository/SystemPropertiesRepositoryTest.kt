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

package com.eltavine.duckdetector.features.systemproperties.data.repository

import com.eltavine.duckdetector.features.systemproperties.data.native.PropAreaFinding
import com.eltavine.duckdetector.features.systemproperties.data.native.ReadOnlyPropertySerialFinding
import com.eltavine.duckdetector.features.systemproperties.data.native.SystemPropertiesNativeSnapshot
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodOutcome
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SystemPropertiesRepositoryTest {

    private val repository = SystemPropertiesRepository()

    @Test
    fun `critical ro serial anomaly maps to danger`() {
        val snapshot = SystemPropertiesNativeSnapshot(
            readOnlySerialAvailable = true,
            readOnlySerialCheckedCount = 6,
            readOnlySerialFindingCount = 1,
            readOnlySerialFindings = listOf(
                ReadOnlyPropertySerialFinding(
                    property = "ro.build.fingerprint",
                    suspiciousSampleCount = 3,
                    low24Hex = "0x000002",
                    detail = "Read-only property serial low24 was non-zero in 3/3 native libc sample(s).",
                ),
            ),
        )

        val signals = repository.buildReadOnlySerialSignals(snapshot)
        val method = repository.buildReadOnlySerialMethod(
            readOnlySerialAvailable = snapshot.readOnlySerialAvailable,
            readOnlySerialCheckedCount = snapshot.readOnlySerialCheckedCount,
            readOnlySerialFindingCount = snapshot.readOnlySerialFindingCount,
            readOnlySerialSignals = signals,
        )

        assertEquals(1, signals.size)
        assertEquals(SystemPropertySeverity.DANGER, signals.single().severity)
        assertTrue(signals.single().property.contains("ro.build.fingerprint"))
        assertEquals("1 anomaly(s)", method.summary)
        assertEquals(SystemPropertiesMethodOutcome.DANGER, method.outcome)
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
        val method = repository.buildPropAreaMethod(
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
        val method = repository.buildPropAreaMethod(
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

        val readOnlySignals = repository.buildReadOnlySerialSignals(snapshot)
        val readOnlyMethod = repository.buildReadOnlySerialMethod(
            readOnlySerialAvailable = snapshot.readOnlySerialAvailable,
            readOnlySerialCheckedCount = snapshot.readOnlySerialCheckedCount,
            readOnlySerialFindingCount = snapshot.readOnlySerialFindingCount,
            readOnlySerialSignals = readOnlySignals,
        )
        val signals = repository.buildPropAreaSignals(snapshot)
        val method = repository.buildPropAreaMethod(
            propAreaAvailable = snapshot.propAreaAvailable,
            propAreaContextCount = snapshot.propAreaContextCount,
            propAreaHoleCount = snapshot.propAreaHoleCount,
            propAreaSignals = signals,
        )

        assertTrue(readOnlySignals.isEmpty())
        assertEquals("Unavailable", readOnlyMethod.summary)
        assertEquals(SystemPropertiesMethodOutcome.SUPPORT, readOnlyMethod.outcome)
        assertTrue(signals.isEmpty())
        assertEquals("Unavailable", method.summary)
        assertEquals(SystemPropertiesMethodOutcome.SUPPORT, method.outcome)
    }
}
