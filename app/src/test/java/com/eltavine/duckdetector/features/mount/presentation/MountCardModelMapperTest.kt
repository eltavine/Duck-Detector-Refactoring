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
import com.eltavine.duckdetector.features.mount.domain.MountFinding
import com.eltavine.duckdetector.features.mount.domain.MountFindingGroup
import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity
import com.eltavine.duckdetector.features.mount.domain.MountMethodOutcome
import com.eltavine.duckdetector.features.mount.domain.MountMethodResult
import com.eltavine.duckdetector.features.mount.domain.MountReport
import com.eltavine.duckdetector.features.mount.domain.MountStage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MountCardModelMapperTest {

    private val mapper = MountCardModelMapper()

    @Test
    fun `debug ramdisk mountpoint info does not turn card yellow`() {
        val model = mapper.map(
            report(
                findings = listOf(
                    MountFinding(
                        id = "debug_ramdisk_mountpoint",
                        label = "Debug ramdisk mountpoint",
                        value = "Present",
                        group = MountFindingGroup.ARTIFACTS,
                        severity = MountFindingSeverity.INFO,
                        detail = "/debug_ramdisk",
                    ),
                ),
            ),
        )

        assertEquals(DetectorStatus.allClear(), model.status)
    }

    @Test
    fun `warning finding still maps to warning`() {
        val model = mapper.map(
            report(
                findings = listOf(
                    MountFinding(
                        id = "overlay_warning",
                        label = "Overlay mount",
                        value = "Present",
                        group = MountFindingGroup.RUNTIME,
                        severity = MountFindingSeverity.WARNING,
                        detail = "/system",
                    ),
                ),
            ),
        )

        assertEquals(DetectorStatus.warning(), model.status)
    }

    @Test
    fun `startup preload rows render without creating a new section`() {
        val model = mapper.map(
            report(
                findings = listOf(
                    MountFinding(
                        id = "early_preload_mnt_strings",
                        label = "mntent strings residue",
                        value = "/data/adb/modules",
                        group = MountFindingGroup.ARTIFACTS,
                        severity = MountFindingSeverity.DANGER,
                        detail = "Source=startup preload",
                    ),
                    MountFinding(
                        id = "early_preload_futile_hide",
                        label = "Futile hide",
                        value = "ctime drift",
                        group = MountFindingGroup.CONSISTENCY,
                        severity = MountFindingSeverity.DANGER,
                        detail = "Source=startup preload",
                    ),
                ),
                methods = listOf(
                    MountMethodResult(
                        label = "Startup preload",
                        summary = "2 hit(s)",
                        outcome = MountMethodOutcome.DANGER,
                    ),
                ),
                earlyPreloadAvailable = true,
                earlyPreloadDetected = true,
                earlyPreloadContextValid = false,
                earlyPreloadFindingCount = 2,
            ),
        )

        assertTrue(model.artifactRows.any { it.label == "mntent strings residue" })
        assertTrue(model.consistencyRows.any { it.label == "Futile hide" })
        assertTrue(model.methodRows.any { it.label == "Startup preload" && it.value == "2 hit(s)" })
        assertTrue(model.scanRows.any { it.label == "Startup preload" && it.value == "Detected" })
        assertTrue(model.scanRows.any { it.label == "Preload context" && it.value == "Stale" })
        assertTrue(model.scanRows.any { it.label == "Preload findings" && it.value == "2" })
    }

    @Test
    fun `loading placeholders include startup preload rows`() {
        val model = mapper.map(MountReport.loading())

        assertEquals("Cross-process mount views", model.procMountViewRows.single().label)
        assertEquals("Pending", model.procMountViewRows.single().value)
        assertTrue(model.methodRows.any { it.label == "Startup preload" })
        assertEquals("Startup preload", model.scanRows.first().label)
        assertTrue(model.methodRows.none { it.label == "Cross-process mount views" })
    }

    @Test
    fun `cross process mount view row stays visible when clean`() {
        val model = mapper.map(
            report(
                findings = emptyList(),
                procMountViewProbeAvailable = true,
                procMountViewDistinctCount = 1,
                procMountViewExpectedCount = 1,
                procMountViewPidCount = 40,
                procMountViewDetail = "Scanned 40 pid(s), 40 readable mount table(s).",
            ),
        )

        val row = model.procMountViewRows.single()
        assertEquals("Clean", row.value)
        assertEquals(DetectorStatus.allClear(), row.status)
        assertNull(row.detail)
        assertTrue(row.hiddenCopyText.orEmpty().contains("Scanned PIDs: 40"))
        assertTrue(row.hiddenCopyText.orEmpty().contains("Root token hit: false"))
    }

    @Test
    fun `cross process mount view row copies root token evidence`() {
        val model = mapper.map(
            report(
                findings = emptyList(),
                procMountViewProbeAvailable = true,
                procMountViewDistinctCount = 2,
                procMountViewExpectedCount = 1,
                procMountViewPidCount = 40,
                procMountViewDivergent = true,
                procMountViewTokenHit = true,
                procMountViewTokenKind = "KSU",
                procMountViewTokenDetail = "KSU /data/adb/modules",
                procMountViewDetail = "Direct root token exposed.",
            ),
        )

        val row = model.procMountViewRows.single()
        assertEquals("KSU mount", row.value)
        assertEquals(DetectorStatus.danger(), row.status)
        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals("1", model.headerFacts.single { it.label == "Critical" }.value)
        assertEquals("None", model.headerFacts.single { it.label == "Review" }.value)
        assertEquals("1 critical mount signal(s)", model.verdict)
        assertTrue(row.detail.orEmpty().contains("KSU /data/adb/modules"))
        assertTrue(row.hiddenCopyText.orEmpty().contains("KSU /data/adb/modules"))
        assertTrue(row.hiddenCopyText.orEmpty().contains("Matched token: KSU"))
        assertTrue(row.hiddenCopyText.orEmpty().contains("Matched mountinfo line:"))
        assertTrue(row.hiddenCopyText.orEmpty().contains("Divergent: true"))
    }

    @Test
    fun `cross process mount divergence promotes mount card warning`() {
        val model = mapper.map(
            report(
                findings = emptyList(),
                procMountViewProbeAvailable = true,
                procMountViewDistinctCount = 2,
                procMountViewExpectedCount = 1,
                procMountViewPidCount = 40,
                procMountViewDivergent = true,
            ),
        )

        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals("1", model.headerFacts.single { it.label == "Review" }.value)
        assertEquals("1 mount signal(s) need review", model.verdict)
    }

    @Test
    fun `cross process root token survives local mount scan failure`() {
        val model = mapper.map(
            report(
                stage = MountStage.FAILED,
                findings = emptyList(),
                procMountViewProbeAvailable = true,
                procMountViewTokenHit = true,
                procMountViewTokenKind = "KSU",
                procMountViewTokenDetail = "KSU /data/adb/modules",
            ),
        )

        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals("1 critical mount signal(s)", model.verdict)
        assertEquals(
            "KSU mount",
            model.procMountViewRows.single().value,
        )
    }

    private fun report(
        stage: MountStage = MountStage.READY,
        findings: List<MountFinding>,
        methods: List<MountMethodResult> = emptyList(),
        earlyPreloadAvailable: Boolean = false,
        earlyPreloadDetected: Boolean = false,
        earlyPreloadContextValid: Boolean = false,
        earlyPreloadFindingCount: Int = 0,
        procMountViewProbeAvailable: Boolean = false,
        procMountViewDistinctCount: Int = 0,
        procMountViewExpectedCount: Int = 1,
        procMountViewPidCount: Int = 0,
        procMountViewDivergent: Boolean = false,
        procMountViewTokenHit: Boolean = false,
        procMountViewTokenKind: String = "",
        procMountViewTokenDetail: String = "",
        procMountViewDetail: String = "",
    ): MountReport {
        return MountReport(
            stage = stage,
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
            mountEntryCount = 32,
            mountInfoEntryCount = 32,
            mapLineCount = 128,
            earlyPreloadAvailable = earlyPreloadAvailable,
            earlyPreloadDetected = earlyPreloadDetected,
            earlyPreloadContextValid = earlyPreloadContextValid,
            earlyPreloadFindingCount = earlyPreloadFindingCount,
            findings = findings,
            impacts = emptyList(),
            methods = methods,
            procMountViewProbeAvailable = procMountViewProbeAvailable,
            procMountViewDistinctCount = procMountViewDistinctCount,
            procMountViewExpectedCount = procMountViewExpectedCount,
            procMountViewPidCount = procMountViewPidCount,
            procMountViewDivergent = procMountViewDivergent,
            procMountViewTokenHit = procMountViewTokenHit,
            procMountViewTokenKind = procMountViewTokenKind,
            procMountViewTokenDetail = procMountViewTokenDetail,
            procMountViewDetail = procMountViewDetail,
        )
    }
}
