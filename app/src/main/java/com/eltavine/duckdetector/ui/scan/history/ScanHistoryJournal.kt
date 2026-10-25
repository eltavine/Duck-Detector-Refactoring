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
import com.eltavine.duckdetector.features.dashboard.presentation.model.ScanHistoryCounts
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.util.UUID
import java.util.zip.CRC32
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Append-only local observations; no display-retention limit and no backup/migration. */
internal class ScanHistoryJournal(private val file: File) {
    private val mutex = Mutex()
    private val seen = HashSet<Pair<UUID, Int>>()
    private val mutableCounts = MutableStateFlow(ScanHistoryCounts())
    val counts = mutableCounts.asStateFlow()
    private var initialized = false

    suspend fun load() = mutex.withLock {
        withContext(Dispatchers.IO) { loadOnce() }
    }

    suspend fun record(runId: UUID, session: Int, epochMillis: Long, verdict: HistoricalVerdict) {
        mutex.withLock {
            withContext(Dispatchers.IO) {
                loadOnce()
                val id = runId to session
                if (id in seen) return@withContext
                file.parentFile?.let { parent ->
                    if (!parent.isDirectory && !parent.mkdirs()) throw IOException("Cannot create history directory")
                }
                RandomAccessFile(file, "rw").use { journal ->
                    val completeLength = journal.length() / RECORD_SIZE * RECORD_SIZE
                    if (journal.length() != completeLength) journal.setLength(completeLength)
                    journal.seek(completeLength)
                    journal.write(encode(runId, session, epochMillis, verdict))
                    journal.fd.sync()
                }
                seen.add(id)
                mutableCounts.value = mutableCounts.value.with(verdict)
            }
        }
    }

    private fun loadOnce() {
        if (initialized) return
        var counts = ScanHistoryCounts()
        val recoveredIds = HashSet<Pair<UUID, Int>>()
        if (file.exists()) {
            RandomAccessFile(file, "r").use { journal ->
                val entries = journal.length() / RECORD_SIZE
                var index = 0L
                while (index < entries) {
                    val raw = ByteArray(RECORD_SIZE)
                    journal.readFully(raw)
                    val data = ByteBuffer.wrap(raw)
                    if (data.int != MAGIC || checksum(raw) != ByteBuffer.wrap(raw, RECORD_SIZE - 4, 4).int) {
                        throw IOException("Scan history contains a corrupt record; refusing to discard evidence")
                    }
                    val id = UUID(data.long, data.long) to data.int
                    data.long // Original completion time.
                    val verdict = HistoricalVerdict.entries.getOrNull(data.get().toInt())
                        ?: throw IOException("Unknown history verdict")
                    if (!recoveredIds.add(id)) throw IOException("Duplicate scan history record")
                    counts = counts.with(verdict)
                    index++
                }
            }
        }
        seen.addAll(recoveredIds)
        mutableCounts.value = counts
        initialized = true
    }

    private companion object {
        const val MAGIC = 0x44534831 // DSH1
        const val RECORD_SIZE = 37

        fun encode(runId: UUID, session: Int, epochMillis: Long, verdict: HistoricalVerdict): ByteArray {
            val record = ByteBuffer.allocate(RECORD_SIZE)
                .putInt(MAGIC)
                .putLong(runId.mostSignificantBits)
                .putLong(runId.leastSignificantBits)
                .putInt(session)
                .putLong(epochMillis)
                .put(verdict.ordinal.toByte())
                .array()
            ByteBuffer.wrap(record, RECORD_SIZE - 4, 4).putInt(checksum(record))
            return record
        }

        fun checksum(raw: ByteArray): Int = CRC32().apply {
            update(raw, 0, RECORD_SIZE - 4)
        }.value.toInt()
    }
}
