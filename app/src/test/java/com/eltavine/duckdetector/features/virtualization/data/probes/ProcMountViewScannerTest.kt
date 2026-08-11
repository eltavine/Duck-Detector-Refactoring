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

package com.eltavine.duckdetector.features.virtualization.data.probes

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProcMountViewScannerTest {

    private val scanner = ProcMountViewScanner()

    private val cleanMountInfo = listOf(
        "22 25 8:1 / / rw,relatime - ext4 /dev/block/dm-2 rw,seclabel",
        "30 22 0:28 / /system rw,seclabel - overlay overlay ro,seclabel,lowerdir=/system",
    )

    @Test
    fun `identical mount tables across processes stay clean`() {
        val result = scanner.evaluate(
            pids = listOf("1000", "2000"),
            lineReader = { cleanMountInfo },
        )

        assertTrue(result.available)
        assertEquals(1, result.distinctViewCount)
        assertEquals(1, result.expectedViewCount)
        assertEquals(2, result.scannedPidCount)
        assertFalse(result.divergent)
        assertFalse(result.tokenHit)
    }

    @Test
    fun `divergent mount tables surface hidden mount divergence`() {
        val hiddenView = cleanMountInfo + listOf(
            "55 22 0:29 / /hidden/modules rw,seclabel - overlay overlay ro,seclabel,lowerdir=/hidden/modules",
        )
        val result = scanner.evaluate(
            pids = listOf("1000", "2000"),
            lineReader = { pid -> if (pid == "2000") hiddenView else cleanMountInfo },
        )

        assertTrue(result.available)
        assertEquals(2, result.distinctViewCount)
        assertTrue(result.divergent)
        assertFalse(result.tokenHit)
    }

    @Test
    fun `direct root token in any view is flagged`() {
        val magiskView = listOf(
            "22 25 8:1 / / rw,relatime - ext4 /dev/block/dm-2 rw,seclabel",
            "40 22 8:1 /magisk /system rw,seclabel - overlay overlay ro,seclabel",
        )
        val result = scanner.evaluate(
            pids = listOf("1000", "2000"),
            lineReader = { pid -> if (pid == "2000") magiskView else cleanMountInfo },
        )

        assertTrue(result.available)
        assertTrue(result.tokenHit)
        assertTrue(result.tokenHitDetail.contains("magisk"))
    }

    @Test
    fun `shared propagation group raises expected view count`() {
        val sharedView = listOf(
            "31 26 8:1 / /mnt/foo rw,relatime shared:1 - tmpfs tmpfs rw",
        ) + cleanMountInfo
        val result = scanner.evaluate(
            pids = listOf("1000", "2000"),
            lineReader = { pid -> if (pid == "2000") sharedView else cleanMountInfo },
        )

        assertTrue(result.available)
        assertEquals(2, result.expectedViewCount)
        assertEquals(2, result.distinctViewCount)
        assertFalse(result.divergent)
    }

    @Test
    fun `unreadable processes are skipped`() {
        val result = scanner.evaluate(
            pids = listOf("1000", "3000", "2000"),
            lineReader = { pid -> if (pid == "3000") emptyList() else cleanMountInfo },
        )

        assertTrue(result.available)
        assertEquals(3, result.scannedPidCount)
        assertEquals(1, result.distinctViewCount)
        assertFalse(result.divergent)
    }

    @Test
    fun `all unreadable mount tables are reported unavailable not divergent`() {
        val result = scanner.evaluate(
            pids = listOf("1000", "2000", "3000"),
            lineReader = { emptyList() },
        )

        assertFalse(result.available)
        assertFalse(result.divergent)
        assertTrue(result.detail.contains("no process mount table was readable"))
    }

    @Test
    fun `unavailable scanner when proc directory missing`() {
        val result = ProcMountViewScanner(
            procDirectoryProvider = { java.io.File("/nonexistent-proc-dir") },
        ).scan()

        assertFalse(result.available)
        assertFalse(result.divergent)
    }
}
