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

package com.eltavine.duckdetector.features.mount.data.repository

import com.eltavine.duckdetector.capability.earlypreload.data.EarlyMountPreloadResult
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.mount.data.native.MountNativeBridge
import com.eltavine.duckdetector.features.mount.data.native.MountNativeFinding
import com.eltavine.duckdetector.features.mount.data.native.MountNativeSnapshot
import com.eltavine.duckdetector.features.mount.domain.MountAnonymousDeviceState
import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity
import com.eltavine.duckdetector.features.mount.domain.MountMethodOutcome
import com.eltavine.duckdetector.features.mount.domain.toDetectorStatus
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MountEvidenceClassificationTest {
    @Test
    fun `contextual properties cannot become danger through methods or impacts`() = runBlocking {
        val report = scan(baseline.copy(
            bindMountDetected = true, mountOptionsAnomaly = true,
            namespaceAnomalyDetected = true, mountPropagationAnomaly = true,
            statxMntIdMismatch = true, statxMountRootAnomaly = true,
            statxMountRootAttribute = true, inconsistentMountDetected = true,
            dmVerityBypassDetected = true, busyboxDetected = true, overlayfsKernelSupport = true,
            debugRamdiskDetected = true, hybridMountDetected = true,
            findings = listOf(MountNativeFinding(
                group = "CONSISTENCY", severity = "INFO", label = "Mount source",
                value = "/vendor", detail = "Source=/dev/block/by-name/vendor",
            )),
        ))
        assertTrue(report.dangerFindings.isEmpty())
        assertTrue(report.warningFindings.isEmpty())
        assertTrue(report.impacts.none { it.severity == MountFindingSeverity.DANGER })
        assertTrue(report.methods.none { it.outcome == MountMethodOutcome.DANGER || it.outcome == MountMethodOutcome.WARNING })
        assertEquals(DetectorStatus.allClear(), report.toDetectorStatus())
    }

    @Test
    fun `development remount properties remain review items without identifying root`() = runBlocking {
        val report = scan(baseline.copy(
            systemRwDetected = true, overlayMountDetected = true,
            loopDeviceDetected = true, systemFsTypeAnomaly = true,
            findings = listOf(MountNativeFinding(
                group = "RUNTIME", severity = "WARNING", label = "Overlay mount",
                value = "/system", detail = "Development remount fixture",
            )),
        ))
        assertEquals(DetectorStatus.warning(), report.toDetectorStatus())
        assertTrue(report.dangerFindings.isEmpty())
        assertTrue(report.methods.none { it.outcome == MountMethodOutcome.DANGER })
        assertTrue(report.impacts.none { it.severity == MountFindingSeverity.DANGER })
    }

    @Test
    fun `specific module root remains danger without guessing a manager identity`() = runBlocking {
        val report = scan(baseline.copy(findings = listOf(MountNativeFinding(
            group = "CONSISTENCY", severity = "DANGER", label = "Root mount artifact",
            value = "/system", detail = "root=/adb/modules/example/system",
        ))))
        assertEquals(DetectorStatus.danger(), report.toDetectorStatus())
        assertEquals(MountMethodOutcome.DANGER,
            report.methods.single { it.label == "/proc/self/mountinfo" }.outcome)
    }

    @Test
    fun `failed mount table collection reports limited coverage instead of all clear`() = runBlocking {
        val report = scan(baseline.copy(mountsReadable = false, mountInfoReadable = false))
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), report.toDetectorStatus())
    }

    @Test
    fun `anonymous device gaps stay informational and do not attribute a root manager`() = runBlocking {
        val report = scan(baseline.copy(
            anonymousDeviceState = MountAnonymousDeviceState.OBSERVED,
            anonymousDeviceDetail = "Gap 0:32 can be a freed ID or another namespace.",
        ))
        val observation = report.findings.single { it.id == "anonymous_device_minors" }
        assertEquals("Gaps observed", observation.value)
        assertEquals(MountFindingSeverity.INFO, observation.severity)
        assertEquals(MountAnonymousDeviceState.OBSERVED, report.anonymousDeviceState)
        assertTrue(report.dangerFindings.isEmpty())
        assertTrue(report.warningFindings.isEmpty())
        assertEquals(MountMethodOutcome.SUPPORT,
            report.methods.single { it.label == "Anonymous device minors" }.outcome)
        assertEquals(DetectorStatus.allClear(), report.toDetectorStatus())
    }

    @Test
    fun `limited anonymous device coverage never becomes a clean method or all clear report`() = runBlocking {
        for (state in MountAnonymousDeviceState.entries.filter { it.coverageLimited }) {
            val report = scan(baseline.copy(anonymousDeviceState = state))
            assertEquals(DetectorStatus.info(InfoKind.SUPPORT), report.toDetectorStatus())
            assertEquals(MountMethodOutcome.SUPPORT,
                report.methods.single { it.label == "Anonymous device minors" }.outcome)
            assertTrue(report.dangerFindings.isEmpty())
        }
        val danger = scan(baseline.copy(
            anonymousDeviceState = MountAnonymousDeviceState.UNAVAILABLE,
            findings = listOf(MountNativeFinding(
                "ARTIFACTS", "DANGER", "Root mount artifact", "/system", "/data/adb/modules/example",
            )),
        ))
        assertEquals(DetectorStatus.danger(), danger.toDetectorStatus())
    }

    private suspend fun scan(snapshot: MountNativeSnapshot) = MountRepository(
        nativeBridge = object : MountNativeBridge() {
            override fun collectSnapshot() = snapshot
        },
        preloadResultProvider = { EarlyMountPreloadResult.empty() },
    ).scan()

    private val baseline = MountNativeSnapshot(
        available = true, mountsReadable = true, mountInfoReadable = true,
        mapsReadable = true, filesystemsReadable = true, statxSupported = true,
        initNamespaceReadable = true, anonymousDeviceState = MountAnonymousDeviceState.NO_GAPS,
    )
}
