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

package com.eltavine.duckdetector.features.mount.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.mount.domain.MountReport
import com.eltavine.duckdetector.features.mount.domain.MountStage
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextMarker
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextReport
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MountZygoteNextCardModelMapperTest {

    private val mapper = MountCardModelMapper()

    @Test
    fun `loading card includes pending zygote next row`() {
        val row = mapper.map(MountReport.loading()).procMountViewRows[1]

        assertEquals("Zygote next mount view", row.label)
        assertEquals("Pending", row.value)
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), row.status)
    }

    @Test
    fun `unsupported platform renders support without changing clean verdict`() {
        val model = mapper.map(
            report(
                MountZygoteNextReport(
                    state = MountZygoteNextState.UNSUPPORTED,
                    sdkInt = 36,
                    errorDetail = "Requires Android 17.",
                ),
            ),
        )

        assertEquals("Requires Android 17", model.procMountViewRows[1].value)
        assertEquals(DetectorStatus.allClear(), model.status)
    }

    @Test
    fun `unavailable probe renders support instead of clean`() {
        val model = mapper.map(
            report(
                MountZygoteNextReport(
                    state = MountZygoteNextState.UNAVAILABLE,
                    sdkInt = 37,
                    errorDetail = "Native service binding failed.",
                ),
            ),
        )
        val row = model.procMountViewRows[1]

        assertEquals("Unavailable", row.value)
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), row.status)
        assertEquals("Native service binding failed.", row.detail)
    }

    @Test
    fun `shared contrast is clean and retained in copy evidence`() {
        val model = mapper.map(report(readyReport()))
        val row = model.procMountViewRows[1]

        assertEquals("Clean", row.value)
        assertEquals(DetectorStatus.allClear(), row.status)
        assertTrue(row.hiddenCopyText.orEmpty().contains("Namespace assessment: INIT_MANAGED"))
        assertTrue(row.hiddenCopyText.orEmpty().contains("Shared-view contrast: true"))
    }

    @Test
    fun `unverified init managed view renders support instead of clean`() {
        val zygoteNext = readyReport().copy(isolatedRootMountId = 0L)
        val row = mapper.map(report(zygoteNext)).procMountViewRows[1]

        assertEquals("Coverage unverified", row.value)
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), row.status)
        assertTrue(row.detail.orEmpty().contains("Init-managed namespace coverage is unverified"))
    }

    @Test
    fun `root mount record turns card red and exposes raw evidence`() {
        val model = mapper.map(report(readyReport(rootMarker())))
        val row = model.procMountViewRows[1]

        assertEquals("Root mount", row.value)
        assertEquals(DetectorStatus.danger(), row.status)
        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals("1", model.headerFacts.single { it.label == "Critical" }.value)
        assertTrue(row.detail.orEmpty().contains("/data/adb/modules/example"))
        assertTrue(row.hiddenCopyText.orEmpty().contains("Root marker leak: true"))
    }

    @Test
    fun `debug ramdisk context alone remains clean`() {
        val marker = rootMarker().copy(labels = listOf("debug_ramdisk"))
        val model = mapper.map(report(readyReport(marker)))

        assertEquals("Clean", model.procMountViewRows[1].value)
        assertEquals(DetectorStatus.allClear(), model.status)
    }

    private fun report(zygoteNext: MountZygoteNextReport): MountReport {
        return MountReport(
            stage = MountStage.READY,
            nativeAvailable = true,
            mountsReadable = true,
            mountInfoReadable = true,
            mapsReadable = true,
            filesystemsReadable = true,
            initNamespaceReadable = false,
            statxSupported = true,
            permissionTotal = 4,
            permissionDenied = 0,
            permissionAccessible = 4,
            mountEntryCount = 30,
            mountInfoEntryCount = 30,
            mapLineCount = 100,
            earlyPreloadAvailable = false,
            earlyPreloadDetected = false,
            earlyPreloadContextValid = false,
            earlyPreloadFindingCount = 0,
            findings = emptyList(),
            impacts = emptyList(),
            methods = emptyList(),
            zygoteNext = zygoteNext,
        )
    }

    private fun readyReport(
        vararg markers: MountZygoteNextMarker,
    ): MountZygoteNextReport {
        return MountZygoteNextReport(
            state = MountZygoteNextState.READY,
            sdkInt = 37,
            mainNamespaceInode = 10,
            mainPropagation = "master:1",
            mainRootMountId = 240,
            mainMinimumMountId = 220,
            mainMaximumMountId = 420,
            mainMountCount = 100,
            isolatedNamespaceInode = 20,
            isolatedPropagation = "shared:1",
            isolatedRootMountId = 24,
            isolatedMinimumMountId = 20,
            isolatedMaximumMountId = 210,
            isolatedMountCount = 101,
            isolatedMarkers = markers.toList(),
        )
    }

    private fun rootMarker(): MountZygoteNextMarker {
        return MountZygoteNextMarker(
            labels = listOf("KernelSU", "data/adb"),
            mountPoint = "/data/adb/modules/example",
            mountRoot = "/",
            fileSystemType = "ext4",
            source = "/dev/block/loop7",
            rawLine = "31 1 7:0 / /data/adb/modules/example rw - ext4 /dev/block/loop7 rw",
        )
    }
}
