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
import com.eltavine.duckdetector.features.mount.data.native.MountNativeBridge
import com.eltavine.duckdetector.features.mount.data.native.MountNativeSnapshot
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextMountMarker
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextProbeManager
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextProbeResult
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextProbeState
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextProcessSnapshot
import com.eltavine.duckdetector.features.mount.domain.MountMethodOutcome
import com.eltavine.duckdetector.features.mount.domain.MountStage
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextNamespaceAssessment
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MountZygoteNextRepositoryTest {

    @Test
    fun `isolated root marker becomes one direct mount danger signal`() = runBlocking {
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = readyResult(rootMarker()),
        ).scan()

        assertEquals(MountStage.READY, report.stage)
        assertTrue(report.zygoteNext.leakDetected)
        assertEquals(1, report.dangerSignalCount)
        assertEquals(
            MountMethodOutcome.DANGER,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `shared contrast without root marker remains clean`() = runBlocking {
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = readyResult(),
        ).scan()

        assertTrue(report.zygoteNext.contrastObserved)
        assertEquals(
            MountZygoteNextNamespaceAssessment.INIT_MANAGED,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(0, report.dangerSignalCount)
        assertEquals(0, report.warningSignalCount)
        assertEquals(
            MountMethodOutcome.CLEAN,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `missing mount id ordering is support instead of clean`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(rootMountId = 0L),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.UNVERIFIED,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(
            MountMethodOutcome.SUPPORT,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `shared native root without slave classic root is unverified`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                mainProcess = base.mainProcess.copy(rootPropagation = "shared:1"),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.UNVERIFIED,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(
            MountMethodOutcome.SUPPORT,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `shared and slave classic root is not the aosp zygote signature`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                mainProcess = base.mainProcess.copy(rootPropagation = "shared:2 master:1"),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.UNVERIFIED,
            report.zygoteNext.namespaceAssessment,
        )
    }

    @Test
    fun `matching namespace identities are unverified`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(mountNamespaceInode = 10L),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.UNVERIFIED,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(
            MountMethodOutcome.SUPPORT,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `root marker remains dangerous when namespace coverage is unverified`() = runBlocking {
        val base = readyResult(rootMarker())
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(rootPropagation = "master:1"),
            ),
        ).scan()

        assertTrue(report.zygoteNext.leakDetected)
        assertEquals(
            MountMethodOutcome.DANGER,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `root marker in main process alone remains clean`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                mainProcess = base.mainProcess.copy(markers = listOf(rootMarker())),
            ),
        ).scan()

        assertEquals(0, report.dangerSignalCount)
        assertTrue(report.zygoteNext.dangerousMarkers.isEmpty())
        assertEquals(
            MountMethodOutcome.CLEAN,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `zygote next evidence survives local native mount failure`() = runBlocking {
        val report = repository(
            nativeSnapshot = MountNativeSnapshot(available = false),
            zygoteNextResult = readyResult(rootMarker()),
        ).scan()

        assertEquals(MountStage.FAILED, report.stage)
        assertTrue(report.zygoteNext.leakDetected)
        assertEquals(1, report.dangerSignalCount)
    }

    @Test
    fun `zygote next evidence survives thrown local native mount failure`() = runBlocking {
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = readyResult(rootMarker()),
            nativeFailure = IllegalStateException("native bridge crashed"),
        ).scan()

        assertEquals(MountStage.FAILED, report.stage)
        assertTrue(report.zygoteNext.leakDetected)
        assertEquals(1, report.dangerSignalCount)
        assertEquals("native bridge crashed", report.errorMessage)
    }

    private fun repository(
        nativeSnapshot: MountNativeSnapshot,
        zygoteNextResult: ZygoteNextProbeResult,
        nativeFailure: Throwable? = null,
    ): MountRepository {
        return MountRepository(
            nativeBridge = object : MountNativeBridge() {
                override fun collectSnapshot(): MountNativeSnapshot {
                    nativeFailure?.let { throw it }
                    return nativeSnapshot
                }
            },
            preloadResultProvider = { EarlyMountPreloadResult.empty() },
            zygoteNextProbeManager = object : ZygoteNextProbeManager() {
                override suspend fun collect(): ZygoteNextProbeResult = zygoteNextResult
            },
        )
    }

    private fun readyResult(
        vararg markers: ZygoteNextMountMarker,
    ): ZygoteNextProbeResult {
        return ZygoteNextProbeResult(
            state = ZygoteNextProbeState.READY,
            sdkInt = 37,
            mainProcess = ZygoteNextProcessSnapshot(
                available = true,
                mountNamespaceInode = 10,
                rootPropagation = "master:1",
                rootMountId = 240,
                minimumMountId = 220,
                maximumMountId = 420,
                mountCount = 100,
            ),
            isolatedProcess = ZygoteNextProcessSnapshot(
                available = true,
                mountNamespaceInode = 20,
                rootPropagation = "shared:1",
                rootMountId = 24,
                minimumMountId = 20,
                maximumMountId = 210,
                mountCount = 101,
                markers = markers.toList(),
            ),
        )
    }

    private fun rootMarker(): ZygoteNextMountMarker {
        return ZygoteNextMountMarker(
            labels = listOf("KernelSU", "data/adb"),
            mountPoint = "/data/adb/modules/example",
            mountRoot = "/",
            fileSystemType = "ext4",
            source = "/dev/block/loop7",
            rawLine = "31 1 7:0 / /data/adb/modules/example rw - ext4 /dev/block/loop7 rw",
        )
    }

    private fun cleanSnapshot(): MountNativeSnapshot {
        return MountNativeSnapshot(
            available = true,
            mountsReadable = true,
            mountInfoReadable = true,
            mapsReadable = true,
            filesystemsReadable = true,
            statxSupported = true,
            permissionTotal = 4,
            permissionAccessible = 4,
            mountEntryCount = 30,
            mountInfoEntryCount = 30,
            mapLineCount = 100,
        )
    }
}
