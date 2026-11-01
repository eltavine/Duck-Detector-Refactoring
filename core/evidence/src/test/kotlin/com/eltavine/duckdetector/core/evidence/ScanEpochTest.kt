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

package com.eltavine.duckdetector.core.evidence

import kotlinx.coroutines.async
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class ScanEpochTest {
    @Test fun `parallel detectors inherit the same epoch without reading their own clock`() = runBlocking {
        val batch = ScanEpoch.begin(123_456_789L)
        val children = withContext(batch) {
            val first = async(Dispatchers.Default) { ScanEpoch.current { error("unexpected local clock") } }
            val second = async(Dispatchers.IO) { ScanEpoch.current { error("unexpected local clock") } }
            first.await() to second.await()
        }
        assertEquals(batch.id, children.first.id)
        assertEquals(batch.id, children.second.id)
        assertEquals(batch.startedNanos, children.first.startedNanos)
    }

    @Test fun `separate scans in the same millisecond have different identities`() {
        val a = ScanEpoch.begin(123_123_456L)
        val b = ScanEpoch.begin(123_123_456L)
        assertEquals(a.startedMillis, b.startedMillis)
        assertNotEquals(a.id, b.id)
    }

    @Test fun `standalone detector requests do not inherit an earlier scan`() = runBlocking {
        val a = ScanEpoch.current { 123_123_456L }
        val b = ScanEpoch.current { 123_123_457L }
        assertNotEquals(a.id, b.id)
    }
}
