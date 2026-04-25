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

class EarlyMountPreloadStoreTest {

    @After
    fun tearDown() {
        EarlyMountPreloadStore.resetForTesting()
    }

    @Test
    fun `native stored result beats intent only result`() {
        val nativeResult = EarlyMountPreloadResult(
            hasRun = true,
            detected = true,
            detectionMethod = "FutileHide",
            details = "native",
            futileHideDetected = true,
            isContextValid = false,
            source = EarlyMountPreloadSource.NATIVE,
        ).normalize()
        EarlyMountPreloadStore.replaceBridgeForTesting(FakePreloadBridge(nativeResult))
        EarlyMountPreloadStore.capture(
            mapOf(
                EarlyMountPreloadResult.KEY_HAS_RUN to true,
                EarlyMountPreloadResult.KEY_DETAILS to "intent",
                EarlyMountPreloadResult.KEY_MNT_STRINGS to true,
            ),
        )

        val selected = EarlyMountPreloadStore.currentResult()

        assertEquals(EarlyMountPreloadSource.NATIVE, selected.source)
        assertEquals("native", selected.details)
        assertTrue(selected.futileHideDetected)
        assertFalse(selected.mntStringsDetected)
    }

    @Test
    fun `intent only result is used when native store is unavailable`() {
        EarlyMountPreloadStore.replaceBridgeForTesting(FakePreloadBridge(EarlyMountPreloadResult.empty()))
        EarlyMountPreloadStore.capture(
            mapOf(
                EarlyMountPreloadResult.KEY_HAS_RUN to true,
                EarlyMountPreloadResult.KEY_DETECTED to true,
                EarlyMountPreloadResult.KEY_DETECTION_METHOD to "MntStrings",
                EarlyMountPreloadResult.KEY_MNT_STRINGS to true,
                EarlyMountPreloadResult.KEY_MNT_STRINGS_TARGET to "/data/adb/modules",
            ),
        )

        val selected = EarlyMountPreloadStore.currentResult()

        assertEquals(EarlyMountPreloadSource.INTENT, selected.source)
        assertTrue(selected.hasRun)
        assertTrue(selected.detected)
        assertTrue(selected.mntStringsDetected)
        assertEquals("/data/adb/modules", selected.mntStringsTarget)
    }

    @Test
    fun `empty result stays non detecting and non breaking`() {
        EarlyMountPreloadStore.replaceBridgeForTesting(FakePreloadBridge(EarlyMountPreloadResult.empty()))

        val selected = EarlyMountPreloadStore.currentResult()

        assertFalse(selected.hasRun)
        assertFalse(selected.detected)
        assertEquals(0, selected.findingCount)
        assertTrue(selected.findings.isEmpty())
    }

    private class FakePreloadBridge(
        private val result: EarlyMountPreloadResult,
    ) : EarlyMountPreloadBridge() {
        override fun getStoredResult(): EarlyMountPreloadResult = result
    }
}
