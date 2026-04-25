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

package com.eltavine.duckdetector.features.mount.data.repository

import com.eltavine.duckdetector.core.startup.preload.EarlyMountPreloadResult
import com.eltavine.duckdetector.core.startup.preload.EarlyMountPreloadSource
import com.eltavine.duckdetector.features.mount.data.native.MountNativeBridge
import com.eltavine.duckdetector.features.mount.data.native.MountNativeFinding
import com.eltavine.duckdetector.features.mount.data.native.MountNativeSnapshot
import com.eltavine.duckdetector.features.mount.domain.MountStage
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MountRepositoryTest {

    @Test
    fun `preload only futile hide escalates mount to danger`() = runBlocking {
        val report = MountRepository(
            nativeBridge = FakeMountNativeBridge(snapshot = cleanSnapshot()),
            preloadResultProvider = { preloadResult(futileHideDetected = true) },
        ).scan()

        assertEquals(MountStage.READY, report.stage)
        assertTrue(report.earlyPreloadAvailable)
        assertTrue(report.earlyPreloadDetected)
        assertTrue(report.dangerFindings.any { it.id == "early_preload_futile_hide" })
    }

    @Test
    fun `preload only minor dev gap escalates mount to warning`() = runBlocking {
        val report = MountRepository(
            nativeBridge = FakeMountNativeBridge(snapshot = cleanSnapshot()),
            preloadResultProvider = { preloadResult(minorDevGapDetected = true) },
        ).scan()

        assertEquals(MountStage.READY, report.stage)
        assertTrue(report.earlyPreloadDetected)
        assertTrue(report.warningFindings.any { it.id == "early_preload_minor_dev_gap" })
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

            val mountIdFindings = report.findings.filter { it.label == "Mount ID loophole" }
            assertEquals(1, mountIdFindings.size)
            assertEquals("mount_id_loophole", mountIdFindings.single().id)
            assertTrue(mountIdFindings.single().detail.orEmpty().contains("Startup preload:"))
            assertTrue(mountIdFindings.single().detail.orEmpty().contains("Runtime mountinfo:"))
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
    fun `small preload only data mirror mount id gap is suppressed as false positive`() =
        runBlocking {
            val report = MountRepository(
                nativeBridge = FakeMountNativeBridge(snapshot = cleanSnapshot()),
                preloadResultProvider = {
                    EarlyMountPreloadResult(
                        hasRun = true,
                        detected = true,
                        detectionMethod = "MountIdGap",
                        details = "preload",
                        mountIdGapDetected = true,
                        findings = listOf(
                            "MOUNT_ID_GAP|Missing 2 mount IDs before /data_mirror (first gap 12703-12704)|DANGER",
                        ),
                        source = EarlyMountPreloadSource.NATIVE,
                    ).normalize()
                },
            ).scan()

            assertTrue(report.earlyPreloadAvailable)
            assertFalse(report.earlyPreloadDetected)
            assertTrue(report.findings.none { it.id == "early_preload_mount_id_loophole" })
        }

    @Test
    fun `small preload data mirror gap stays when runtime corroborates mount id loophole`() =
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
                preloadResultProvider = {
                    EarlyMountPreloadResult(
                        hasRun = true,
                        detected = true,
                        detectionMethod = "MountIdGap",
                        details = "preload",
                        mountIdGapDetected = true,
                        findings = listOf(
                            "MOUNT_ID_GAP|Missing 2 mount IDs before /data_mirror (first gap 12703-12704)|DANGER",
                        ),
                        source = EarlyMountPreloadSource.NATIVE,
                    ).normalize()
                },
            ).scan()

            assertTrue(report.earlyPreloadDetected)
            assertTrue(report.findings.any { it.label == "Mount ID loophole" })
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
}
