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

import com.eltavine.duckdetector.features.nativeroot.data.native.CgroupProcessLeakNativeEntry
import com.eltavine.duckdetector.features.nativeroot.data.native.CgroupProcessLeakNativePath
import com.eltavine.duckdetector.features.nativeroot.data.native.CgroupProcessLeakNativeSnapshot
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CgroupProcessLeakProbeTest {

    private val probe = CgroupProcessLeakProbe()

    @Test
    fun `confirmed hidden suspicious process keeps selective visibility at danger`() {
        val result = probe.evaluate(
            nativeSnapshot = CgroupProcessLeakNativeSnapshot(
                available = true,
                pathCheckCount = 32,
                accessiblePathCount = 1,
                processCount = 1,
                procDeniedCount = 0,
                paths = listOf(
                    CgroupProcessLeakNativePath(
                        path = "/sys/fs/cgroup/uid_0",
                        uid = 0,
                        accessible = true,
                        pidCount = 1,
                    ),
                ),
                entries = listOf(
                    CgroupProcessLeakNativeEntry(
                        uidPath = "/sys/fs/cgroup/uid_0",
                        cgroupUid = 0,
                        pid = 4242,
                        procUid = 2000,
                        startTimeTicks = 998877L,
                        killErrno = 1,
                        sid = 123,
                        sidErrno = 0,
                        pgid = 456,
                        pgidErrno = 0,
                        schedulerPolicy = 0,
                        schedulerErrno = 0,
                        pidfdErrno = 0,
                        procContext = "u:r:su:s0",
                        comm = "lspd",
                        cmdline = "/system/bin/lspd",
                    ),
                ),
            ),
            javaView = CgroupProcessJavaView(
                checkedPathCount = 32,
                accessiblePaths = emptySet(),
                pidEntriesByPath = emptyMap(),
            ),
        )

        assertEquals(4, result.findings.size)
        assertTrue(
            result.findings.any {
                it.label == "Cgroup UID mismatch" &&
                        it.severity == NativeRootFindingSeverity.WARNING
            },
        )
        assertTrue(
            result.findings.any {
                it.label == "LSPosed companion residue" &&
                        it.severity == NativeRootFindingSeverity.WARNING
            },
        )
        assertTrue(
            result.findings.any {
                it.label == "LSPosed root-context process" &&
                        it.severity == NativeRootFindingSeverity.WARNING
            },
        )
        assertTrue(
            result.findings.any {
                it.label == "Selective cgroup visibility" &&
                        it.severity == NativeRootFindingSeverity.DANGER
            },
        )
        assertEquals(4, result.hitCount)
    }

    @Test
    fun `unconfirmed hidden suspicious process downgrades visibility to warning`() {
        val result = probe.evaluate(
            nativeSnapshot = CgroupProcessLeakNativeSnapshot(
                available = true,
                pathCheckCount = 32,
                accessiblePathCount = 1,
                processCount = 1,
                procDeniedCount = 1,
                paths = listOf(
                    CgroupProcessLeakNativePath(
                        path = "/sys/fs/cgroup/uid_0",
                        uid = 0,
                        accessible = true,
                        pidCount = 1,
                    ),
                ),
                entries = listOf(
                    CgroupProcessLeakNativeEntry(
                        uidPath = "/sys/fs/cgroup/uid_0",
                        cgroupUid = 0,
                        pid = 3131,
                        procUid = 0,
                        procContext = "u:r:init:s0",
                        comm = "lspd",
                        cmdline = "/system/bin/lspd",
                    ),
                ),
            ),
            javaView = CgroupProcessJavaView(
                checkedPathCount = 32,
                accessiblePaths = emptySet(),
                pidEntriesByPath = emptyMap(),
            ),
        )

        assertTrue(
            result.findings.any {
                it.label == "Selective cgroup visibility" &&
                        it.severity == NativeRootFindingSeverity.WARNING
            },
        )
        assertTrue(
            result.findings.none {
                it.label == "Selective cgroup visibility" &&
                        it.severity == NativeRootFindingSeverity.DANGER
            },
        )
    }

    @Test
    fun `self pid is excluded from cgroup findings`() {
        val result = probe.evaluate(
            nativeSnapshot = CgroupProcessLeakNativeSnapshot(
                available = true,
                pathCheckCount = 32,
                accessiblePathCount = 1,
                processCount = 1,
                procDeniedCount = 0,
                paths = listOf(
                    CgroupProcessLeakNativePath(
                        path = "/sys/fs/cgroup/uid_2000",
                        uid = 2000,
                        accessible = true,
                        pidCount = 1,
                    ),
                ),
                entries = listOf(
                    CgroupProcessLeakNativeEntry(
                        uidPath = "/sys/fs/cgroup/uid_2000",
                        cgroupUid = 2000,
                        pid = 5151,
                        procUid = 2000,
                        startTimeTicks = 999L,
                        killErrno = 0,
                        sid = 5151,
                        sidErrno = 0,
                        pgid = 5151,
                        pgidErrno = 0,
                        schedulerPolicy = 0,
                        schedulerErrno = 0,
                        pidfdErrno = 0,
                        procContext = "u:r:su:s0",
                        comm = "lspd",
                        cmdline = "/system/bin/lspd",
                    ),
                ),
            ),
            javaView = CgroupProcessJavaView(
                checkedPathCount = 32,
                accessiblePaths = emptySet(),
                pidEntriesByPath = emptyMap(),
            ),
            selfPid = 5151,
        )

        assertTrue(result.findings.isEmpty())
        assertEquals(0, result.hitCount)
    }

    @Test
    fun `clean snapshot stays clean`() {
        val result = probe.evaluate(
            nativeSnapshot = CgroupProcessLeakNativeSnapshot(
                available = true,
                pathCheckCount = 32,
                accessiblePathCount = 1,
                processCount = 1,
                procDeniedCount = 0,
                paths = listOf(
                    CgroupProcessLeakNativePath(
                        path = "/sys/fs/cgroup/uid_2000",
                        uid = 2000,
                        accessible = true,
                        pidCount = 1,
                    ),
                ),
                entries = listOf(
                    CgroupProcessLeakNativeEntry(
                        uidPath = "/sys/fs/cgroup/uid_2000",
                        cgroupUid = 2000,
                        pid = 5151,
                        procUid = 2000,
                        procContext = "u:r:untrusted_app:s0:c1,c2",
                        comm = "app_process64",
                        cmdline = "com.eltavine.duckdetector",
                    ),
                ),
            ),
            javaView = CgroupProcessJavaView(
                checkedPathCount = 32,
                accessiblePaths = setOf("/sys/fs/cgroup/uid_2000"),
                pidEntriesByPath = mapOf("/sys/fs/cgroup/uid_2000" to setOf(5151)),
            ),
        )

        assertTrue(result.available)
        assertTrue(result.findings.isEmpty())
        assertEquals(0, result.hitCount)
    }
}
