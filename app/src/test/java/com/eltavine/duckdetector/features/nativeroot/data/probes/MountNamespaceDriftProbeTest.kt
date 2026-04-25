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

import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteProfile
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MountNamespaceDriftProbeTest {

    private val probe = MountNamespaceDriftProbe()

    @Test
    fun `isolated mount anchor drift maps to warning finding`() {
        val result = probe.evaluate(
            localSnapshot = LocalMountNamespaceSnapshot(
                namespaceInode = "mnt:[41]",
                systemMountKey = "10|8:1|/|/system|ext4|/dev/block/dm-1",
            ),
            isolatedSnapshot = VirtualizationRemoteSnapshot(
                available = true,
                profile = VirtualizationRemoteProfile.ISOLATED,
                mountNamespaceInode = "mnt:[42]",
                systemMountKey = "11|0:22|/|/system|overlay|overlay",
            ),
        )

        assertTrue(result.available)
        assertTrue(result.isolatedProcessAvailable)
        assertEquals(1, result.mountAnchorDriftCount)
        assertEquals(1, result.signalCount)
        assertEquals("Isolated mount anchor drift", result.findings.single().label)
        assertEquals(NativeRootFindingSeverity.WARNING, result.findings.single().severity)
        assertTrue(result.findings.single().detail.contains("/system"))
    }

    @Test
    fun `namespace drift without comparable anchors still surfaces review finding`() {
        val result = probe.evaluate(
            localSnapshot = LocalMountNamespaceSnapshot(
                namespaceInode = "mnt:[100]",
            ),
            isolatedSnapshot = VirtualizationRemoteSnapshot(
                available = true,
                profile = VirtualizationRemoteProfile.ISOLATED,
                mountNamespaceInode = "mnt:[101]",
            ),
        )

        assertTrue(result.available)
        assertEquals(0, result.mountAnchorDriftCount)
        assertEquals(1, result.signalCount)
        assertEquals("Isolated mount namespace drift", result.findings.single().label)
        assertTrue(result.findings.single().detail.contains("mnt:[100]"))
        assertTrue(result.findings.single().detail.contains("mnt:[101]"))
    }
}
