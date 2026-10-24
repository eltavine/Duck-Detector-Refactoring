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
import com.eltavine.duckdetector.capability.earlypreload.data.EarlyMountPreloadSource
import com.eltavine.duckdetector.capability.helperprocess.data.HelperProcessProfile
import com.eltavine.duckdetector.capability.helperprocess.data.HelperProcessSnapshot
import com.eltavine.duckdetector.capability.helperprocess.data.IsolatedHelperProbeManager
import com.eltavine.duckdetector.capability.helperprocess.data.ProcMountViewRootToken
import com.eltavine.duckdetector.features.mount.data.native.MountNativeBridge
import com.eltavine.duckdetector.features.mount.data.native.MountNativeFinding
import com.eltavine.duckdetector.features.mount.data.native.MountNativeSnapshot
import com.eltavine.duckdetector.features.mount.domain.MountAnonymousDeviceState
import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity
import com.eltavine.duckdetector.features.mount.domain.MountMethodOutcome
import com.eltavine.duckdetector.features.mount.domain.toDetectorStatus
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.features.mount.domain.MountRootToken
import com.eltavine.duckdetector.features.mount.domain.MountStage
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MountRepositoryTest {

    @Test
    fun `preload proc inode timestamp is informational`() = runBlocking {
        val report = MountRepository(
            nativeBridge = FakeMountNativeBridge(snapshot = cleanSnapshot()),
            preloadResultProvider = { preloadResult(futileHideDetected = true) },
        ).scan()

        assertEquals(MountStage.READY, report.stage)
        assertTrue(report.earlyPreloadAvailable)
        assertTrue(report.earlyPreloadDetected)
        assertTrue(report.findings.any { it.id == "early_preload_futile_hide" && it.severity == MountFindingSeverity.INFO })
        assertTrue(report.dangerFindings.isEmpty())
    }

    @Test
    fun `preload minor device allocation is informational`() = runBlocking {
        val report = MountRepository(
            nativeBridge = FakeMountNativeBridge(snapshot = cleanSnapshot()),
            preloadResultProvider = { preloadResult(minorDevGapDetected = true) },
        ).scan()

        assertEquals(MountStage.READY, report.stage)
        assertTrue(report.earlyPreloadDetected)
        assertTrue(report.findings.any { it.id == "early_preload_minor_dev_gap" && it.severity == MountFindingSeverity.INFO })
        assertTrue(report.warningFindings.isEmpty())
        assertTrue(report.dangerFindings.isEmpty())
    }

    @Test
    fun `preload mount id gap plus runtime mount id loophole yields one merged finding`() =
        runBlocking {
            val snapshot = cleanSnapshot().copy(
                findings = listOf(
                    MountNativeFinding(
                        group = "CONSISTENCY",
                        severity = "DANGER",
                        label = "Mount ID loophole",
                        value = "Gap after ART",
                        detail = "Expected next ID 12, got 15",
                    ),
                ),
                mountIdLoopholeDetected = true,
            )

            val report = MountRepository(
                nativeBridge = FakeMountNativeBridge(snapshot = snapshot),
                preloadResultProvider = { preloadResult(mountIdGapDetected = true) },
            ).scan()

            val mountIdFindings = report.findings.filter { it.label == MOUNT_ID_OBSERVATION_LABEL }
            assertEquals(1, mountIdFindings.size)
            assertEquals("mount_id_loophole", mountIdFindings.single().id)
            assertEquals(MountFindingSeverity.INFO, mountIdFindings.single().severity)
            assertEquals(DetectorStatus.allClear(), report.toDetectorStatus())
            assertTrue(report.impacts.none { it.severity == MountFindingSeverity.DANGER })
            assertEquals(MountMethodOutcome.SUPPORT, report.methods.single { it.label == "Startup preload" }.outcome)
            assertEquals(MountMethodOutcome.SUPPORT, report.methods.single { it.label == "/proc/self/mountinfo" }.outcome)
            assertTrue(mountIdFindings.single().detail.orEmpty().contains("Startup preload:"))
            assertTrue(mountIdFindings.single().detail.orEmpty().contains("Runtime mountinfo:"))
        }

    @Test
    fun `busybox and VFS mount root attributes are informational`() = runBlocking {
        val report = MountRepository(
            nativeBridge = FakeMountNativeBridge(
                snapshot = cleanSnapshot().copy(busyboxDetected = true, statxMountRootAttribute = true),
            ),
            preloadResultProvider = { EarlyMountPreloadResult.empty() },
        ).scan()

        assertEquals(MountMethodOutcome.SUPPORT, report.methods.single { it.label == "Path probes" }.outcome)
        assertEquals(MountMethodOutcome.SUPPORT, report.methods.single { it.label == "statx cross-check" }.outcome)
    }

    @Test
    fun `unconfirmed statx capture difference is informational`() = runBlocking {
        val report = MountRepository(
            nativeBridge = FakeMountNativeBridge(snapshot = cleanSnapshot().copy(statxMountRootAnomaly = true)),
            preloadResultProvider = { EarlyMountPreloadResult.empty() },
        ).scan()

        assertEquals(MountMethodOutcome.SUPPORT, report.methods.single { it.label == "statx cross-check" }.outcome)
    }

    @Test
    fun `no preload result keeps current mount behavior unchanged`() = runBlocking {
        val snapshot = cleanSnapshot().copy(
            findings = listOf(
                MountNativeFinding(
                    group = "ARTIFACTS",
                    severity = "WARNING",
                    label = "Runtime only",
                    value = "Present",
                    detail = "/system",
                ),
            ),
        )

        val report = MountRepository(
            nativeBridge = FakeMountNativeBridge(snapshot = snapshot),
            preloadResultProvider = { EarlyMountPreloadResult.empty() },
        ).scan()

        assertFalse(report.earlyPreloadAvailable)
        assertTrue(report.findings.any { it.label == "Runtime only" })
        assertTrue(report.findings.none { it.id.startsWith("early_preload_") })
    }

    @Test
    fun `stale preload context still merges stored evidence but marks context as non fresh`() =
        runBlocking {
            val report = MountRepository(
                nativeBridge = FakeMountNativeBridge(snapshot = cleanSnapshot()),
                preloadResultProvider = {
                    preloadResult(
                        futileHideDetected = true,
                        contextValid = false,
                    )
                },
            ).scan()

            assertTrue(report.earlyPreloadAvailable)
            assertFalse(report.earlyPreloadContextValid)
            assertTrue(report.findings.any { it.id == "early_preload_futile_hide" })
        }

    @Test
    fun `preload mount id observations of any size remain visible without risk escalation`() = runBlocking {
        for (count in listOf(1, 2, 3, 8, 16)) {
            val message = "Missing $count mount IDs before /data_mirror (first gap 12703-12704)"
            val report = MountRepository(
                nativeBridge = FakeMountNativeBridge(snapshot = cleanSnapshot()),
                preloadResultProvider = {
                    preloadResult(mountIdGapDetected = true).copy(
                        findings = listOf("MOUNT_ID_GAP|$message|DANGER"),
                    )
                },
            ).scan()

            val finding = report.findings.single { it.id == "early_preload_mount_id_loophole" }
            assertTrue(finding.detail.orEmpty().contains(message))
            assertEquals(MountFindingSeverity.INFO, finding.severity)
            assertEquals(DetectorStatus.allClear(), report.toDetectorStatus())
            assertTrue(report.dangerFindings.isEmpty())
            assertTrue(report.warningFindings.isEmpty())
            assertTrue(report.impacts.none { it.severity == MountFindingSeverity.DANGER })
            assertEquals(MountMethodOutcome.SUPPORT, report.methods.single { it.label == "Startup preload" }.outcome)
        }
    }

    @Test
    fun `runtime only legacy mount id gap cannot escalate methods impacts or report`() = runBlocking {
        val report = MountRepository(
            nativeBridge = FakeMountNativeBridge(snapshot = cleanSnapshot().copy(
                mountIdLoopholeDetected = true,
                findings = listOf(MountNativeFinding(
                    group = "CONSISTENCY", severity = "DANGER", label = "Mount ID loophole",
                    value = "Gap after ART", detail = "Expected next ID 12, got 15",
                )),
            )),
            preloadResultProvider = { EarlyMountPreloadResult.empty() },
        ).scan()

        assertEquals(MountFindingSeverity.INFO, report.findings.single { it.id != "anonymous_device_minors" }.severity)
        assertEquals(DetectorStatus.allClear(), report.toDetectorStatus())
        assertEquals(MountMethodOutcome.SUPPORT, report.methods.single { it.label == "/proc/self/mountinfo" }.outcome)
        assertTrue(report.impacts.none { it.severity == MountFindingSeverity.DANGER })
    }

    @Test
    fun `restricted paths and init namespace do not corroborate a mount id observation`() = runBlocking {
        val report = MountRepository(
            nativeBridge = FakeMountNativeBridge(snapshot = cleanSnapshot().copy(
                initNamespaceReadable = false, permissionDenied = 4, permissionAccessible = 0,
            )),
            preloadResultProvider = { preloadResult(mountIdGapDetected = true) },
        ).scan()

        assertTrue(report.findings.any { it.id == "permission_coverage" })
        assertTrue(report.findings.any { it.id == "init_namespace_scope" })
        assertTrue(report.findings.all { it.severity == MountFindingSeverity.INFO })
        assertEquals(DetectorStatus.allClear(), report.toDetectorStatus())
    }

    @Test
    fun `mount id observations do not dilute direct root mount artifacts`() = runBlocking {
        for (label in listOf("Magisk mounts", "KernelSU or magic-mount overlay")) {
            val report = MountRepository(
                nativeBridge = FakeMountNativeBridge(snapshot = cleanSnapshot().copy(
                    magiskMountDetected = label == "Magisk mounts",
                    ksuOverlayDetected = label == "KernelSU or magic-mount overlay",
                    findings = listOf(MountNativeFinding(
                        group = "CONSISTENCY", severity = "DANGER", label = label,
                        value = "Present", detail = "Independent evidence",
                    )),
                )),
                preloadResultProvider = { preloadResult(mountIdGapDetected = true) },
            ).scan()

            assertEquals(label, report.dangerFindings.single().label)
            assertEquals(DetectorStatus.danger(), report.toDetectorStatus())
        }
    }

    @Test
    fun `isolated proc mount evidence is owned by mount report`() = runBlocking {
        val report = MountRepository(
            nativeBridge = FakeMountNativeBridge(snapshot = cleanSnapshot()),
            preloadResultProvider = { EarlyMountPreloadResult.empty() },
            isolatedProbeManager = FakeIsolatedProbeManager(
                HelperProcessSnapshot(
                    available = true,
                    profile = HelperProcessProfile.ISOLATED,
                    procMountViewAvailable = true,
                    procMountViewCount = 2,
                    procMountViewExpected = 1,
                    procMountViewPidCount = 40,
                    procMountViewDivergent = true,
                    procMountViewTokenHit = true,
                    procMountViewToken = ProcMountViewRootToken.ADB,
                    procMountViewTokenDetail = "/data/adb/modules/example",
                    procMountViewDetail = "Two views and a direct token.",
                ),
            ),
        ).scan()

        assertTrue(report.procMountViewProbeAvailable)
        assertEquals(2, report.procMountViewDistinctCount)
        assertEquals(1, report.procMountViewExpectedCount)
        assertEquals(40, report.procMountViewPidCount)
        assertTrue(report.procMountViewDivergent)
        assertTrue(report.procMountViewTokenHit)
        assertEquals(MountRootToken.ADB, report.procMountViewRootToken)
    }

    private fun cleanSnapshot(): MountNativeSnapshot {
        return MountNativeSnapshot(
            available = true,
            mountsReadable = true,
            mountInfoReadable = true,
            mapsReadable = true,
            filesystemsReadable = true,
            initNamespaceReadable = true,
            statxSupported = true,
            permissionTotal = 4,
            permissionDenied = 0,
            permissionAccessible = 4,
            mountEntryCount = 32,
            mountInfoEntryCount = 32,
            mapLineCount = 128,
            anonymousDeviceState = MountAnonymousDeviceState.NO_GAPS,
        )
    }

    private fun preloadResult(
        futileHideDetected: Boolean = false,
        mountIdGapDetected: Boolean = false,
        minorDevGapDetected: Boolean = false,
        contextValid: Boolean = true,
    ): EarlyMountPreloadResult {
        return EarlyMountPreloadResult(
            hasRun = true,
            detected = futileHideDetected || mountIdGapDetected || minorDevGapDetected,
            detectionMethod = "Preload",
            details = "preload",
            futileHideDetected = futileHideDetected,
            mountIdGapDetected = mountIdGapDetected,
            minorDevGapDetected = minorDevGapDetected,
            isContextValid = contextValid,
            source = EarlyMountPreloadSource.NATIVE,
        ).normalize()
    }

    private class FakeMountNativeBridge(
        private val snapshot: MountNativeSnapshot,
    ) : MountNativeBridge() {
        override fun collectSnapshot(): MountNativeSnapshot = snapshot
    }

    private class FakeIsolatedProbeManager(
        private val snapshot: HelperProcessSnapshot,
    ) : IsolatedHelperProbeManager() {
        override suspend fun collectProcMountView(): HelperProcessSnapshot = snapshot
    }
}
