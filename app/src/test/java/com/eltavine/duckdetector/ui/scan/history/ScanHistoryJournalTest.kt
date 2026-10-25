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

package com.eltavine.duckdetector.ui.scan.history

import com.eltavine.duckdetector.features.dashboard.presentation.model.HistoricalVerdict
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.util.UUID
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ScanHistoryJournalTest {
    @Test fun storesAllEventsAcrossRestartsAndDeduplicatesSessions() = runTest {
        withJournal { file ->
            val id = UUID.randomUUID()
            val first = ScanHistoryJournal(file)
            first.record(id, 1, 10L, HistoricalVerdict.DANGER)
            first.record(id, 1, 10L, HistoricalVerdict.DANGER)
            first.record(id, 2, 20L, HistoricalVerdict.WARNING)
            first.record(id, 3, 30L, HistoricalVerdict.CLEAR)
            first.record(id, 4, 40L, HistoricalVerdict.INCONCLUSIVE)
            val restored = ScanHistoryJournal(file)
            restored.load()
            assertEquals(1L, restored.counts.value.danger)
            assertEquals(1L, restored.counts.value.warning)
            assertEquals(1L, restored.counts.value.clear)
            assertEquals(1L, restored.counts.value.inconclusive)
            restored.record(id, 4, 40L, HistoricalVerdict.INCONCLUSIVE)
            restored.record(UUID.randomUUID(), 1, 50L, HistoricalVerdict.CLEAR)
            assertEquals(2L, ScanHistoryJournal(file).apply { load() }.counts.value.clear)
        }
    }

    @Test fun unfinishedTailDoesNotEraseCompletedEntries() = runTest {
        withJournal { file ->
            val id = UUID.randomUUID()
            ScanHistoryJournal(file).record(id, 1, 10L, HistoricalVerdict.DANGER)
            file.appendBytes(byteArrayOf(1, 2, 3))
            val restored = ScanHistoryJournal(file)
            restored.load()
            restored.record(id, 2, 20L, HistoricalVerdict.CLEAR)
            assertEquals(2L, (file.length() / 37))
            assertEquals(1L, restored.counts.value.danger)
            assertEquals(1L, restored.counts.value.clear)
        }
    }

    @Test fun corruptionIsNotSilentlyTreatedAsEmptyHistory() = runTest {
        withJournal { file ->
            ScanHistoryJournal(file).record(UUID.randomUUID(), 1, 10L, HistoricalVerdict.WARNING)
            RandomAccessFile(file, "rw").use { it.seek(10); it.write(0x7f) }
            assertThrows(java.io.IOException::class.java) {
                kotlinx.coroutines.runBlocking { ScanHistoryJournal(file).load() }
            }
        }
    }

    private suspend fun withJournal(test: suspend (File) -> Unit) {
        val folder = Files.createTempDirectory("duck-scan-history").toFile()
        try {
            test(File(folder, "events.bin"))
        } finally {
            folder.deleteRecursively()
        }
    }
}
