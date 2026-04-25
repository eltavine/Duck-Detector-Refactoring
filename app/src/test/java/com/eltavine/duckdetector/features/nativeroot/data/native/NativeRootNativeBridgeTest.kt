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
                KERNELSU=1
                APATCH=0
                MAGISK=1
                SUSFS=0
                KSU_VERSION=12000
                PRCTL_HIT=1
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
        assertTrue(snapshot.kernelSuDetected)
        assertTrue(snapshot.magiskDetected)
        assertEquals(12000L, snapshot.kernelSuVersion)
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
    fun `parse falls back safely on blank raw data`() {
        val snapshot = bridge.parse("")

        assertFalse(snapshot.available)
        assertTrue(snapshot.findings.isEmpty())
        assertEquals(0, snapshot.pathHitCount)
    }

    @Test
    fun `should skip ksu supercall on xiaomi family devices`() {
        assertTrue(
            bridge.shouldSkipKsuSupercall(
                manufacturer = "Xiaomi",
                brand = "Redmi",
            )
        )
        assertTrue(
            bridge.shouldSkipKsuSupercall(
                manufacturer = "POCO",
                brand = "poco",
            )
        )
    }

    @Test
    fun `should keep ksu supercall on non xiaomi devices`() {
        assertFalse(
            bridge.shouldSkipKsuSupercall(
                manufacturer = "Google",
                brand = "google",
            )
        )
    }
}
