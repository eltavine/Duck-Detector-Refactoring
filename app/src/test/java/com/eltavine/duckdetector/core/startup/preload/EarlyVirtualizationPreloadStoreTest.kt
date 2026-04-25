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

package com.eltavine.duckdetector.core.startup.preload

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EarlyVirtualizationPreloadStoreTest {

    @After
    fun tearDown() {
        EarlyVirtualizationPreloadStore.resetForTesting()
    }

    @Test
    fun `native stored result beats intent only result`() {
        val nativeResult = EarlyVirtualizationPreloadResult(
            hasRun = true,
            detected = true,
            detectionMethod = "QEMU property",
            details = "native",
            mountNamespaceInode = "mnt:[1]",
            apexMountKey = "apex-native",
            qemuPropertyDetected = true,
            source = EarlyVirtualizationPreloadSource.NATIVE,
        ).normalize()
        EarlyVirtualizationPreloadStore.replaceBridgeForTesting(FakeBridge(nativeResult))
        EarlyVirtualizationPreloadStore.capture(
            mapOf(
                EarlyVirtualizationPreloadResult.KEY_HAS_RUN to true,
                EarlyVirtualizationPreloadResult.KEY_NATIVE_BRIDGE to true,
                EarlyVirtualizationPreloadResult.KEY_DETAILS to "intent",
                EarlyVirtualizationPreloadResult.KEY_MOUNT_NAMESPACE_INODE to "mnt:[2]",
                EarlyVirtualizationPreloadResult.KEY_APEX_MOUNT_KEY to "apex-intent",
            ),
        )

        val selected = EarlyVirtualizationPreloadStore.currentResult()

        assertEquals(EarlyVirtualizationPreloadSource.NATIVE, selected.source)
        assertEquals("native", selected.details)
        assertTrue(selected.qemuPropertyDetected)
        assertFalse(selected.nativeBridgeDetected)
        assertEquals("mnt:[1]", selected.mountNamespaceInode)
        assertEquals("apex-native", selected.apexMountKey)
    }

    @Test
    fun `intent only result is used when native store is unavailable`() {
        EarlyVirtualizationPreloadStore.replaceBridgeForTesting(
            FakeBridge(EarlyVirtualizationPreloadResult.empty()),
        )
        EarlyVirtualizationPreloadStore.capture(
            mapOf(
                EarlyVirtualizationPreloadResult.KEY_HAS_RUN to true,
                EarlyVirtualizationPreloadResult.KEY_DETECTED to true,
                EarlyVirtualizationPreloadResult.KEY_AVF_RUNTIME to true,
                EarlyVirtualizationPreloadResult.KEY_DETAILS to "intent",
                EarlyVirtualizationPreloadResult.KEY_MOUNT_NAMESPACE_INODE to "mnt:[3]",
                EarlyVirtualizationPreloadResult.KEY_SYSTEM_MOUNT_KEY to "system-intent",
            ),
        )

        val selected = EarlyVirtualizationPreloadStore.currentResult()

        assertEquals(EarlyVirtualizationPreloadSource.INTENT, selected.source)
        assertTrue(selected.avfRuntimeDetected)
        assertTrue(selected.detected)
        assertEquals("mnt:[3]", selected.mountNamespaceInode)
        assertEquals("system-intent", selected.systemMountKey)
    }

    @Test
    fun `empty result stays non detecting and non breaking`() {
        EarlyVirtualizationPreloadStore.replaceBridgeForTesting(
            FakeBridge(EarlyVirtualizationPreloadResult.empty()),
        )

        val selected = EarlyVirtualizationPreloadStore.currentResult()

        assertFalse(selected.hasRun)
        assertFalse(selected.detected)
        assertEquals(0, selected.findingCount)
        assertTrue(selected.findings.isEmpty())
    }

    private class FakeBridge(
        private val result: EarlyVirtualizationPreloadResult,
    ) : EarlyVirtualizationPreloadBridge() {
        override fun getStoredResult(): EarlyVirtualizationPreloadResult = result
    }
}
