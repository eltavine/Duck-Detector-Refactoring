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

package com.eltavine.duckdetector.features.nativeroot.presentation

import com.eltavine.duckdetector.core.ui.model.DetectionSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodOutcome
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodResult
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootStage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeRootCardModelMapperTest {

    private val mapper = NativeRootCardModelMapper()

    @Test
    fun `cgroup leakage contributes method and scan rows`() {
        val report = NativeRootReport(
            stage = NativeRootStage.READY,
            findings = listOf(
                NativeRootFinding(
                    id = "cgroup_visibility_4242",
                    label = "Selective cgroup visibility",
                    value = "PID 4242",
                    detail = "Java File view missed a PID that native getdents exposed.",
                    group = NativeRootGroup.PROCESS,
                    severity = NativeRootFindingSeverity.DANGER,
                ),
            ),
            kernelSuDetected = false,
            aPatchDetected = false,
            magiskDetected = false,
            susfsDetected = false,
            kernelSuVersion = 0L,
            nativeAvailable = true,
            prctlProbeHit = false,
            susfsProbeHit = false,
            pathHitCount = 0,
            pathCheckCount = 12,
            processHitCount = 0,
            processCheckedCount = 4,
            processDeniedCount = 1,
            cgroupAvailable = true,
            cgroupPathCheckCount = 32,
            cgroupAccessiblePathCount = 2,
            cgroupProcessCheckedCount = 3,
            cgroupProcDeniedCount = 1,
            cgroupHitCount = 1,
            kernelHitCount = 0,
            kernelSourceCount = 3,
            propertyHitCount = 0,
            propertyCheckCount = 5,
            methods = listOf(
                NativeRootMethodResult(
                    label = "cgroupLeakage",
                    summary = "1 hit(s)",
                    outcome = NativeRootMethodOutcome.DETECTED,
                    detail = "Enumerate per-UID cgroup trees and compare native vs Java visibility.",
                ),
            ),
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.DANGER, model.status.severity)
        assertTrue(model.subtitle.contains("cgroup", ignoreCase = true))
        assertTrue(model.methodRows.any { it.label == "cgroupLeakage" && it.value == "1 hit(s)" })
        assertEquals("32", model.scanRows.single { it.label == "Cgroup paths" }.value)
        assertEquals("1", model.scanRows.single { it.label == "Cgroup hits" }.value)
        assertTrue(model.runtimeRows.any { it.label == "Selective cgroup visibility" })
    }

    @Test
    fun `blocked ksu supercall is shown as support not clean`() {
        val report = NativeRootReport(
            stage = NativeRootStage.READY,
            findings = emptyList(),
            kernelSuDetected = false,
            aPatchDetected = false,
            magiskDetected = false,
            susfsDetected = false,
            kernelSuVersion = 0L,
            nativeAvailable = true,
            prctlProbeHit = false,
            susfsProbeHit = false,
            pathHitCount = 0,
            pathCheckCount = 12,
            processHitCount = 0,
            processCheckedCount = 4,
            processDeniedCount = 0,
            cgroupAvailable = false,
            cgroupPathCheckCount = 0,
            cgroupAccessiblePathCount = 0,
            cgroupProcessCheckedCount = 0,
            cgroupProcDeniedCount = 0,
            cgroupHitCount = 0,
            kernelHitCount = 0,
            kernelSourceCount = 3,
            propertyHitCount = 0,
            propertyCheckCount = 5,
            methods = listOf(
                NativeRootMethodResult(
                    label = "ksuReadonlySupercall",
                    summary = "Blocked",
                    outcome = NativeRootMethodOutcome.SUPPORT,
                    detail = "reboot() helper was blocked by seccomp.",
                ),
            ),
            ksuSupercallAttempted = true,
            ksuSupercallBlocked = true,
        )

        val model = mapper.map(report)

        assertTrue(model.summary.contains("blocked by app seccomp"))
        assertEquals("Limited", model.headerFacts.single { it.label == "Direct" }.value)
        assertTrue(
            model.nativeRows.any {
                it.label == "KSU supercall" && it.value == "Blocked by seccomp"
            }
        )
        assertTrue(model.methodRows.any { it.label == "ksuReadonlySupercall" && it.value == "Blocked" })
    }

    @Test
    fun `mount drift and manager fingerprint land in runtime method and scan rows`() {
        val report = NativeRootReport(
            stage = NativeRootStage.READY,
            findings = listOf(
                NativeRootFinding(
                    id = "mount_anchor_drift_isolated",
                    label = "Isolated mount anchor drift",
                    value = "1 anchor(s)",
                    detail = "/system main=dev=8:1 root=/ point=/system fs=ext4 source=/dev/block/dm-1 isolated=dev=0:22 root=/ point=/system fs=overlay source=overlay",
                    group = NativeRootGroup.PROCESS,
                    severity = NativeRootFindingSeverity.WARNING,
                    detailMonospace = true,
                ),
                NativeRootFinding(
                    id = "ksu_manager_manifest",
                    label = "KernelSU manager manifest",
                    value = "3/3 traits",
                    detail = "package=me.weishu.kernelsu",
                    group = NativeRootGroup.PACKAGE,
                    severity = NativeRootFindingSeverity.WARNING,
                    detailMonospace = true,
                ),
            ),
            kernelSuDetected = false,
            aPatchDetected = false,
            magiskDetected = false,
            susfsDetected = false,
            kernelSuVersion = 0L,
            nativeAvailable = true,
            prctlProbeHit = false,
            susfsProbeHit = false,
            pathHitCount = 0,
            pathCheckCount = 12,
            processHitCount = 0,
            processCheckedCount = 4,
            processDeniedCount = 0,
            cgroupAvailable = true,
            cgroupPathCheckCount = 32,
            cgroupAccessiblePathCount = 2,
            cgroupProcessCheckedCount = 3,
            cgroupProcDeniedCount = 0,
            cgroupHitCount = 0,
            kernelHitCount = 0,
            kernelSourceCount = 3,
            propertyHitCount = 0,
            propertyCheckCount = 5,
            methods = listOf(
                NativeRootMethodResult(
                    label = "isolatedMountDrift",
                    summary = "1 anchor(s)",
                    outcome = NativeRootMethodOutcome.WARNING,
                    detail = "Compared mount anchors.",
                ),
                NativeRootMethodResult(
                    label = "ksuManagerFingerprint",
                    summary = "3/3 traits",
                    outcome = NativeRootMethodOutcome.WARNING,
                    detail = "Manager manifest fingerprint.",
                ),
            ),
            isolatedMountProbeAvailable = true,
            mainMountNamespaceInode = "mnt:[41]",
            isolatedMountNamespaceInode = "mnt:[42]",
            mountDriftSignalCount = 1,
            mountAnchorDriftCount = 1,
            ksuManagerPackagePresent = true,
            ksuManagerTraitHitCount = 3,
        )

        val model = mapper.map(report)

        assertTrue(model.runtimeRows.any { it.label == "Isolated mount anchor drift" })
        assertTrue(model.runtimeRows.any { it.label == "KernelSU manager manifest" })
        assertTrue(model.methodRows.any { it.label == "isolatedMountDrift" && it.value == "1 anchor(s)" })
        assertTrue(model.methodRows.any { it.label == "ksuManagerFingerprint" && it.value == "3/3 traits" })
        assertEquals("mnt:[41]", model.scanRows.single { it.label == "Main mnt ns" }.value)
        assertEquals("mnt:[42]", model.scanRows.single { it.label == "Isolated mnt ns" }.value)
        assertEquals("1", model.scanRows.single { it.label == "Mount drift hits" }.value)
        assertEquals("Present", model.scanRows.single { it.label == "Manager package" }.value)
        assertEquals("3/3", model.scanRows.single { it.label == "Manager traits" }.value)
    }

    @Test
    fun `warning path hits stay warning in scan rows`() {
        val report = NativeRootReport(
            stage = NativeRootStage.READY,
            findings = listOf(
                NativeRootFinding(
                    id = "path_resetprop_tmp",
                    label = "resetprop tmp residue",
                    value = "Present",
                    detail = "Category: Shell tmp artifact\nConfirmations: 2/3\nEvidence: stat, openat\n/data/local/tmp/resetprop",
                    group = NativeRootGroup.PATH,
                    severity = NativeRootFindingSeverity.WARNING,
                    detailMonospace = true,
                ),
            ),
            kernelSuDetected = false,
            aPatchDetected = false,
            magiskDetected = false,
            susfsDetected = false,
            kernelSuVersion = 0L,
            nativeAvailable = true,
            prctlProbeHit = false,
            susfsProbeHit = false,
            pathHitCount = 1,
            pathCheckCount = 36,
            processHitCount = 0,
            processCheckedCount = 4,
            processDeniedCount = 0,
            cgroupAvailable = true,
            cgroupPathCheckCount = 32,
            cgroupAccessiblePathCount = 0,
            cgroupProcessCheckedCount = 0,
            cgroupProcDeniedCount = 0,
            cgroupHitCount = 0,
            kernelHitCount = 0,
            kernelSourceCount = 3,
            propertyHitCount = 0,
            propertyCheckCount = 5,
            methods = emptyList(),
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.WARNING, model.status.severity)
        assertEquals(DetectionSeverity.WARNING, model.scanRows.single { it.label == "Path hits" }.status.severity)
        assertTrue(model.runtimeRows.any { it.label == "resetprop tmp residue" })
    }
}
