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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
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

    @Test fun corruptRecordIsArchivedAndHealthyRecordsRemainWritable() = runTest {
        withJournal { file ->
            val id = UUID.randomUUID()
            val journal = ScanHistoryJournal(file)
            journal.record(id, 1, 10L, HistoricalVerdict.WARNING)
            journal.record(id, 2, 20L, HistoricalVerdict.DANGER)
            journal.record(id, 3, 30L, HistoricalVerdict.CLEAR)
            val original = file.readBytes()
            RandomAccessFile(file, "rw").use { it.seek(37L + 10L); it.write(0x7f) }
            val damaged = file.readBytes()
            val restored = ScanHistoryJournal(file)
            restored.load()
            val issue = restored.issue.value as ScanHistoryJournal.Issue.Recovered
            assertEquals(1L, issue.discardedRecords)
            assertEquals(damaged.toList(), File(file.parentFile, issue.backupName).readBytes().toList())
            assertTrue(!original.contentEquals(damaged))
            assertEquals(2L * 37L, file.length())
            assertEquals(1L, restored.counts.value.warning)
            assertEquals(0L, restored.counts.value.danger)
            assertEquals(1L, restored.counts.value.clear)
            restored.record(id, 4, 40L, HistoricalVerdict.DANGER)
            assertEquals(1L, ScanHistoryJournal(file).apply { load() }.counts.value.danger)
        }
    }

    @Test fun queuedCompletionWritesRemainOrderedAndDeduplicated() = runTest {
        withJournal { file ->
            val journal = ScanHistoryJournal(file)
            val id = UUID.randomUUID()
            repeat(50) { session ->
                journal.enqueue(id, session + 1, session.toLong(), HistoricalVerdict.CLEAR)
            }
            journal.enqueue(id, 50, 50L, HistoricalVerdict.DANGER)
            withContext(Dispatchers.IO) {
                withTimeout(10_000) { journal.counts.first { it.clear == 50L } }
            }
            assertEquals(50L, journal.counts.value.clear)
            assertEquals(0L, journal.counts.value.danger)
            assertEquals(50L * 37L, file.length())
        }
    }

    @Test fun unreadableHistoryIsReportedWithoutResettingCounters() = runTest {
        val folder = Files.createTempDirectory("duck-unreadable-history").toFile()
        try {
            val journal = ScanHistoryJournal(folder)
            assertThrows(java.io.IOException::class.java) {
                kotlinx.coroutines.runBlocking { journal.load() }
            }
            assertTrue(journal.issue.value is ScanHistoryJournal.Issue.Failed)
            assertEquals(0L, journal.counts.value.coloredTotal)
        } finally {
            folder.deleteRecursively()
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
