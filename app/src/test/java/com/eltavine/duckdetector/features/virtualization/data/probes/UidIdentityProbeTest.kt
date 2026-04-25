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

package com.eltavine.duckdetector.features.virtualization.data.probes

import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity
import org.junit.Assert.assertTrue
import org.junit.Test

class UidIdentityProbeTest {

    private val probe = UidIdentityProbe()

    @Test
    fun `packages for uid containing host package maps to danger`() {
        val result = probe.evaluate(
            uid = 10123,
            applicationUid = 10123,
            packageName = "com.eltavine.duckdetector",
            processName = "com.eltavine.duckdetector",
            uidName = "u0_a123",
            packagesForUid = listOf("com.eltavine.duckdetector", "com.vmos.pro"),
        )

        assertTrue(
            result.signals.any {
                it.label == "Host package shares UID" &&
                        it.severity == VirtualizationSignalSeverity.DANGER
            },
        )
        assertTrue(result.hostPackageHit)
    }

    @Test
    fun `missing own package maps to danger`() {
        val result = probe.evaluate(
            uid = 10123,
            applicationUid = 10123,
            packageName = "com.eltavine.duckdetector",
            processName = "com.eltavine.duckdetector",
            uidName = "u0_a123",
            packagesForUid = listOf("com.example.other"),
        )

        assertTrue(
            result.signals.any {
                it.label == "Current package missing from UID" &&
                        it.severity == VirtualizationSignalSeverity.DANGER
            },
        )
    }

    @Test
    fun `blank uid name maps to warning`() {
        val result = probe.evaluate(
            uid = 10123,
            applicationUid = 10123,
            packageName = "com.eltavine.duckdetector",
            processName = "com.eltavine.duckdetector",
            uidName = "",
            packagesForUid = listOf("com.eltavine.duckdetector"),
        )

        assertTrue(
            result.signals.any {
                it.label == "UID name unavailable" &&
                        it.severity == VirtualizationSignalSeverity.WARNING
            },
        )
    }
}
