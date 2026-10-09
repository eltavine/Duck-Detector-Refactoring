/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.features.heapresidue.data.retention

import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueRetention
import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Test

class HeapDumpRetentionTest {
    @Test fun disabledStoreDoesNotCreateDirectory() {
        val root = Files.createTempDirectory("heap-retention").toFile()
        try {
            val directory = root.resolve("disabled")
            val retention = HeapDumpRetention(directory, false)
            retention.wrap(byteArrayOf(1, 2).inputStream()).readBytes()
            assertEquals(HeapResidueRetention.DISABLED, retention.finish(true))
            assertFalse(directory.exists())
        } finally { root.deleteRecursively() }
    }
    @Test fun rollingStoreKeepsTwoAndDeletesIncompleteCaptures() {
        val directory = Files.createTempDirectory("heap-retention").toFile()
        try {
            repeat(4) {
                val retention = HeapDumpRetention(directory, true)
                retention.wrap(byteArrayOf(1, 2, 3).inputStream()).readBytes()
                assertEquals(HeapResidueRetention.SAVED, retention.finish(true))
            }
            assertEquals(2, directory.listFiles()!!.size)
            val incomplete = HeapDumpRetention(directory, true)
            incomplete.wrap(byteArrayOf(1).inputStream()).readBytes()
            incomplete.finish(false)
            assertTrue(directory.listFiles()!!.all { it.extension == "hprof" })
        } finally { directory.deleteRecursively() }
    }
    @Test fun retentionFailureDoesNotInterruptInput() {
        val file = Files.createTempFile("not-a-directory", ".tmp").toFile()
        try {
            val retention = HeapDumpRetention(file, true)
            assertArrayEquals(byteArrayOf(1, 2), retention.wrap(byteArrayOf(1, 2).inputStream()).readBytes())
            assertEquals(HeapResidueRetention.FAILED, retention.finish(true))
        } finally { file.delete() }
    }
    @Test fun oversizedDumpIsNotRetainedButInputIsFullyRead() {
        val directory = Files.createTempDirectory("heap-retention").toFile()
        try {
            val bytes = ByteArray(32 * 1024 * 1024 + 1)
            val retention = HeapDumpRetention(directory, true)
            val wrapped = retention.wrap(bytes.inputStream())
            val buffer = ByteArray(8192)
            var count = 0L
            while (true) { val n = wrapped.read(buffer); if (n < 0) break; count += n }
            assertEquals(bytes.size.toLong(), count)
            assertEquals(HeapResidueRetention.TOO_LARGE, retention.finish(true))
            assertTrue(directory.listFiles()!!.isEmpty())
        } finally { directory.deleteRecursively() }
    }
    @Test fun reservesByteBudgetAndRemovesCrashSpoolsBeforeWriting() {
        val directory = Files.createTempDirectory("heap-retention").toFile()
        try {
            val old = directory.resolve("old.hprof")
            java.io.RandomAccessFile(old, "rw").use { it.setLength(33L * 1024 * 1024) }
            directory.resolve("crash.part").writeBytes(byteArrayOf(1))
            val retention = HeapDumpRetention(directory, true)
            assertFalse(old.exists())
            assertFalse(directory.resolve("crash.part").exists())
            retention.wrap(byteArrayOf(1, 2).inputStream()).readBytes()
            assertEquals(HeapResidueRetention.SAVED, retention.finish(true))
            assertTrue(directory.listFiles()!!.sumOf { it.length() } <= 64L * 1024 * 1024)
        } finally { directory.deleteRecursively() }
    }

}
