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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KernelSuManagerFingerprintProbeTest {

    private val probe = KernelSuManagerFingerprintProbe()

    @Test
    fun `run without context returns unavailable`() {
        val result = probe.run()

        assertFalse(result.available)
        assertFalse(result.packagePresent)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `manager manifest traits map to warning fingerprint`() {
        val result = probe.evaluate(
            packageVisibility = InstalledPackageVisibility.FULL,
            snapshot = KernelSuManagerManifestSnapshot(
                versionName = "1.0.0",
                zygotePreloadName = "me.weishu.kernelsu.magica.AppZygotePreload",
                isolatedProcessServices = listOf("me.weishu.kernelsu.magica.MagicaService"),
                appZygoteServices = listOf("me.weishu.kernelsu.magica.MagicaService"),
            ),
        )

        assertTrue(result.available)
        assertTrue(result.packagePresent)
        assertEquals(3, result.traitHitCount)
        assertEquals("KernelSU manager manifest", result.findings.single().label)
        assertEquals("3/3 traits", result.findings.single().value)
        assertTrue(result.detail.contains("zygotePreloadName"))
        assertTrue(result.detail.contains("isolatedProcess services"))
        assertTrue(result.detail.contains("useAppZygote services"))
    }
}
