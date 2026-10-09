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

package com.eltavine.duckdetector.features.heapresidue.data.hprof

import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.FilterInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Host-only reproducible throughput sample; this does not benchmark ART or the Binder pipe. */
class ArtHprofBenchmarkTest {
    @Test fun largePayloadIsSkippedInBlocksWithBoundedReadCount() {
        val target = "com.target.app"
        val bytes = HprofFixture(classFirst = false).string("x".repeat(16 * 1024 * 1024))
            .string("--package-name=$target").finish()
        var calls = 0
        val source = object : FilterInputStream(ByteArrayInputStream(bytes)) {
            override fun read(): Int { calls++; return super.read() }
            override fun read(b: ByteArray, off: Int, len: Int): Int { calls++; return super.read(b, off, len) }
        }
        val result = ArtHprofScanner(setOf(target)).scan(BufferedInputStream(source, 64 * 1024))
        assertEquals(target, result.signals.single().packageName)
        assertEquals(bytes.size.toLong(), result.bytesRead)
        assertTrue("Payload must be read in blocks, not per character", calls < 400)
        val measurements = LongArray(9)
        repeat(3) { ArtHprofScanner(setOf(target)).scan(ByteArrayInputStream(bytes)) }
        repeat(measurements.size) { iteration ->
            val start = System.nanoTime()
            ArtHprofScanner(setOf(target)).scan(ByteArrayInputStream(bytes))
            measurements[iteration] = System.nanoTime() - start
        }
        measurements.sort()
        println("Synthetic bytes=" + bytes.size + "; median_ns=" + measurements[4] + "; buffered_source_reads=" + calls)
    }
}
