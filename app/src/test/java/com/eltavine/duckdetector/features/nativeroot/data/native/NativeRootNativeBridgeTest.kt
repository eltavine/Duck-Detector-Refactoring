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

package com.eltavine.duckdetector.features.nativeroot.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeRootNativeBridgeTest {

    private val bridge = NativeRootNativeBridge()

    @Test
    fun `parse decodes snapshot entries and findings`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                ROOT_FOUND=1
                KERNELSU=1
                APATCH=0
                MAGISK=1
                SUSFS=0
                KSU_VERSION=12000
                PRCTL_HIT=1
                KERNELPATCH_SIDE_CHANNEL_ATTACK=1
                KERNELPATCH_SIDE_CHANNEL_DETAIL=Full: 8.1 us, Empty: 3.2 us, Diff: 4.9 us
                KERNELPATCH_SUPERKEY=1
                KERNELPATCH_SUPERKEY_AVAILABLE=1
                KERNELPATCH_SUPERKEY_CHECKED=4
                KERNELPATCH_SUPERKEY_HITS=3
                KERNELPATCH_SUPERKEY_DETAIL=Probed attempts: 4, page faulted in: 3, pre-resident: 0, control resident: 0, mincore errors: 0
                DEVPTS_ABNORMAL_PERMISSION_FOUND=1
                DEVPTS_ABNORMAL_PERMISSION_AVAILABLE=0
                DEVPTS_ABNORMAL_PERMISSION_CHECKED=2
                DEVPTS_ABNORMAL_PERMISSION_DENIED=1
                DEVPTS_ABNORMAL_PERMISSION_DETAIL=Test: /dev/pts/1\nOwner: 0\nSELinux: u:object_r:ksu_file:s0\nFound KernelSU file Domain
                PERMISSION_BOUNDARY_FOUND=1
                PERMISSION_BOUNDARY_AVAILABLE=1
                PERMISSION_BOUNDARY_DETAIL=Netlink boundary: sendto(RTM_GETLINK) succeeded (SELinux bypass detected).\nMount boundary: /data_mirror directory is accessible.
                KSU_SUPERCALL_ATTEMPTED=1
                KSU_SUPERCALL_HIT=1
                KSU_SUPERCALL_BLOCKED=0
                KSU_SUPERCALL_SAFE_MODE=1
                KSU_SUPERCALL_LKM=1
                KSU_SUPERCALL_LATE_LOAD=1
                KSU_SUPERCALL_PR_BUILD=0
                KSU_SUPERCALL_MANAGER=0
                SUSFS_HIT=0
                SELF_SU_DOMAIN=1
                SELF_CONTEXT=u:r:su:s0
                SELF_KSU_DRIVER_FDS=1
                SELF_KSU_FDWRAPPER_FDS=2
                PATH_HITS=2
                PATH_CHECKS=12
                PROCESS_HITS=1
                PROCESS_CHECKED=9
                PROCESS_DENIED=40
                KERNEL_HITS=1
                KERNEL_SOURCES=3
                PROPERTY_HITS=1
                PROPERTY_CHECKS=5
                FINDING=SYSCALL	DANGER	KernelSU prctl	v12000	prctl(0xDEADBEEF, 2) returned version 12000.
                FINDING=PATH	DANGER	KernelSU daemon	Present	/data/adb/ksud
                FINDING=KERNEL	WARNING	Kernel symbols	1 hit(s)	/proc/kallsyms matched: ksu_
                FINDING=PROPERTY	DANGER	KernelSU property	Set	ro.kernel.ksu=12000\nextra
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.rootDetected)
        assertTrue(snapshot.kernelSuDetected)
        assertTrue(snapshot.magiskDetected)
        assertEquals(12000L, snapshot.kernelSuVersion)
        assertTrue(snapshot.kernelPatchSideChannel)
        assertTrue(snapshot.kernelPatchSuperkey)
        assertTrue(snapshot.kernelPatchSuperkeyAvailable)
        assertEquals(4, snapshot.kernelPatchSuperkeyCheckedCount)
        assertEquals(3, snapshot.kernelPatchSuperkeyHitCount)
        assertTrue(snapshot.kernelPatchSuperkeyDetail.contains("page faulted in: 3"))
        assertTrue(snapshot.devptsAbnormalPermission)
        assertFalse(snapshot.devptsAbnormalPermissionAvailable)
        assertEquals(2, snapshot.devptsAbnormalPermissionCheckedCount)
        assertEquals(1, snapshot.devptsAbnormalPermissionDeniedCount)
        assertTrue(snapshot.devptsAbnormalPermissionDetail.contains("Found KernelSU file Domain"))
        assertTrue(snapshot.permissionBoundaryDetected)
        assertTrue(snapshot.permissionBoundaryAvailable)
        assertTrue(snapshot.permissionBoundaryDetail.contains("Netlink boundary"))
        assertTrue(snapshot.ksuSupercallAttempted)
        assertTrue(snapshot.ksuSupercallProbeHit)
        assertFalse(snapshot.ksuSupercallBlocked)
        assertTrue(snapshot.ksuSupercallSafeMode)
        assertTrue(snapshot.ksuSupercallLkm)
        assertTrue(snapshot.ksuSupercallLateLoad)
        assertTrue(snapshot.selfSuDomain)
        assertEquals("u:r:su:s0", snapshot.selfContext)
        assertEquals(1, snapshot.selfKsuDriverFdCount)
        assertEquals(2, snapshot.selfKsuFdwrapperFdCount)
        assertEquals(4, snapshot.findings.size)
        assertEquals("PROPERTY", snapshot.findings.last().group)
        assertTrue(snapshot.findings.last().detail.contains('\n'))
    }

    @Test
    fun `parse keeps clean superkey state non-detecting`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                KERNELPATCH_SUPERKEY=0
                KERNELPATCH_SUPERKEY_AVAILABLE=1
                KERNELPATCH_SUPERKEY_CHECKED=4
                KERNELPATCH_SUPERKEY_HITS=0
                KERNELPATCH_SUPERKEY_DETAIL=Probed attempts: 4, page faulted in: 0, pre-resident: 0, control resident: 0, control unmapped: 0, page unmapped: 0, mincore errors: 0, usable: yes
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertFalse(snapshot.kernelPatchSuperkey)
        assertTrue(snapshot.kernelPatchSuperkeyAvailable)
        assertEquals(4, snapshot.kernelPatchSuperkeyCheckedCount)
        assertEquals(0, snapshot.kernelPatchSuperkeyHitCount)
    }

    @Test
    fun `parse keeps unusable control guard result unavailable despite a positive checked count`() {
        // A resident control page means the run is unusable. The native side
        // still reports completed attempts in CHECKED, so AVAILABLE is what
        // has to carry the distinction; otherwise this would read as Clean.
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                KERNELPATCH_SUPERKEY=0
                KERNELPATCH_SUPERKEY_AVAILABLE=0
                KERNELPATCH_SUPERKEY_CHECKED=4
                KERNELPATCH_SUPERKEY_HITS=0
                KERNELPATCH_SUPERKEY_DETAIL=Probed attempts: 4, page faulted in: 0, pre-resident: 0, control resident: 1, control unmapped: 0, page unmapped: 0, mincore errors: 0, usable: no
            """.trimIndent(),
        )

        assertFalse(snapshot.kernelPatchSuperkey)
        assertFalse(snapshot.kernelPatchSuperkeyAvailable)
        assertEquals(4, snapshot.kernelPatchSuperkeyCheckedCount)
        assertTrue(snapshot.kernelPatchSuperkeyDetail.contains("usable: no"))
    }

    @Test
    fun `parse keeps mincore error result unavailable`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                KERNELPATCH_SUPERKEY=0
                KERNELPATCH_SUPERKEY_AVAILABLE=0
                KERNELPATCH_SUPERKEY_CHECKED=4
                KERNELPATCH_SUPERKEY_HITS=0
                KERNELPATCH_SUPERKEY_DETAIL=Probed attempts: 4, page faulted in: 0, pre-resident: 0, control resident: 0, control unmapped: 0, page unmapped: 0, mincore errors: 1, usable: no
            """.trimIndent(),
        )

        assertFalse(snapshot.kernelPatchSuperkey)
        assertFalse(snapshot.kernelPatchSuperkeyAvailable)
        assertTrue(snapshot.kernelPatchSuperkeyDetail.contains("mincore errors: 1"))
    }

    @Test
    fun `parse falls back safely on blank raw data`() {
        val snapshot = bridge.parse("")

        assertFalse(snapshot.available)
        assertTrue(snapshot.findings.isEmpty())
        assertEquals(0, snapshot.pathHitCount)
    }

    @Test
    fun `parse preserves seccomp blocked supercall state`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                KSU_SUPERCALL_ATTEMPTED=1
                KSU_SUPERCALL_BLOCKED=1
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.ksuSupercallAttempted)
        assertTrue(snapshot.ksuSupercallBlocked)
        assertFalse(snapshot.ksuSupercallProbeHit)
    }

    @Test
    fun `parse preserves netlink hardware mac leak finding and details`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                MAGISK=1
                PERMISSION_BOUNDARY_FOUND=1
                PERMISSION_BOUNDARY_AVAILABLE=1
                PERMISSION_BOUNDARY_DETAIL=Netlink link boundary: hardware MAC leak detected on wlan0 (12:34:56:78:9a:bc) (SELinux bypass detected).
                FINDING=PERMISSION_BOUNDARY	DANGER	AF_NETLINK MAC Leak	Hardware MAC Exposed (wlan0)	SELinux permission boundary breach: physical MAC leaked on wlan0 (12:34:56:78:9a:bc) on API 36 (AOSP neverallow rule bypassed by Magisk sepolicy injection).
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.magiskDetected)
        assertTrue(snapshot.permissionBoundaryDetected)
        assertTrue(snapshot.permissionBoundaryAvailable)
        assertTrue(snapshot.permissionBoundaryDetail.contains("hardware MAC leak detected on wlan0"))
        assertEquals(1, snapshot.findings.size)
        val finding = snapshot.findings.first()
        assertEquals("PERMISSION_BOUNDARY", finding.group)
        assertEquals("AF_NETLINK MAC Leak", finding.label)
        assertEquals("Hardware MAC Exposed (wlan0)", finding.value)
        assertTrue(finding.detail.contains("Magisk sepolicy injection"))
    }

    @Test
    fun `parse preserves netlink neighbor table leak finding and details`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                MAGISK=1
                PERMISSION_BOUNDARY_FOUND=1
                PERMISSION_BOUNDARY_AVAILABLE=1
                PERMISSION_BOUNDARY_DETAIL=Netlink link boundary: clean (physical interface MAC securely masked or unavailable).\nNetlink neigh boundary: neighbor table leak detected (192.168.1.1 12:34:56:78:9a:bc) (SELinux bypass detected).
                FINDING=PERMISSION_BOUNDARY	DANGER	AF_NETLINK Neighbor Leak	Hardware ARP/Neighbor Exposed	SELinux permission boundary breach: ARP/neighbor entry leaked (192.168.1.1 -> 12:34:56:78:9a:bc) on API 36 (AOSP netlink_route_socket getneigh restriction bypassed).
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.magiskDetected)
        assertTrue(snapshot.permissionBoundaryDetected)
        assertTrue(snapshot.permissionBoundaryAvailable)
        assertTrue(snapshot.permissionBoundaryDetail.contains("neighbor table leak detected"))
        assertEquals(1, snapshot.findings.size)
        val finding = snapshot.findings.first()
        assertEquals("PERMISSION_BOUNDARY", finding.group)
        assertEquals("AF_NETLINK Neighbor Leak", finding.label)
        assertEquals("Hardware ARP/Neighbor Exposed", finding.value)
        assertTrue(finding.detail.contains("getneigh restriction bypassed"))
    }

}


