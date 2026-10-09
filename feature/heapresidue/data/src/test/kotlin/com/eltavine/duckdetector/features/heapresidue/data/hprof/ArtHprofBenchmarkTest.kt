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

import java.io.ByteArrayInputStream
import java.io.FilterInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Host-only reproducible throughput sample; this does not benchmark ART or the Binder pipe. */
class ArtHprofBenchmarkTest {
    private val target = "com.target.app"

    @Test fun largePayloadIsSkippedInBlocksWithBoundedReadCount() {
        val bytes = HprofFixture(classFirst = false).string("x".repeat(16 * 1024 * 1024))
            .string("--package-name=$target").finish()
        measure("large-array", bytes)
    }

    @Test fun objectHeavySegmentsAreDecodedFromBlocks() {
        val bytes = HprofFixture(classFirst = false).objects(200_000).string("--package-name=$target").finish()
        measure("object-heavy", bytes)
    }

    // The scanner owns its buffering, so the source sees only block reads in either heap shape.
    private fun measure(name: String, bytes: ByteArray) {
        val source = CountingStream(bytes)
        val result = ArtHprofScanner(setOf(target)).scan(source)
        assertEquals(target, result.signals.single().packageName)
        assertEquals(bytes.size.toLong(), result.bytesRead)
        assertTrue("Records must be read in blocks, not per byte", source.calls <= bytes.size / (64 * 1024) + 2)
        repeat(5) { ArtHprofScanner(setOf(target)).scan(ByteArrayInputStream(bytes)) }
        val measurements = LongArray(9) {
            val start = System.nanoTime()
            ArtHprofScanner(setOf(target)).scan(ByteArrayInputStream(bytes))
            System.nanoTime() - start
        }
        measurements.sort()
        println("Synthetic $name bytes=${bytes.size}; median_ns=${measurements[4]}; source_reads=${source.calls}")
    }

    private class CountingStream(bytes: ByteArray) : FilterInputStream(ByteArrayInputStream(bytes)) {
        var calls = 0
        override fun read(): Int { calls++; return super.read() }
        override fun read(b: ByteArray, off: Int, len: Int): Int { calls++; return super.read(b, off, len) }
    }
}
