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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

import com.eltavine.duckdetector.core.evidence.ScanEpoch
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ScanSharedCollectionTest {

    private val initial = ScanEpoch.begin(100_000_000L)
    private val shared = ScanSharedCollection<String>()

    @Test
    fun `failed preload is shared within one scan but a later scan may recover`() = runTest {
        var attempts = 0
        val first = shared.collect(initial) { attempts++; "preload missing" }
        val second = shared.collect(initial) { attempts++; "should not run" }
        val recovered = shared.collect(ScanEpoch.begin(200_000_000L)) { attempts++; "collected" }
        assertEquals("preload missing", first)
        assertEquals(first, second)
        assertEquals("collected", recovered)
        assertEquals(2, attempts)
    }

    @Test
    fun `detectors of the same scan share one collection`() = runTest {
        var collections = 0
        val first = shared.collect(initial) { collections++; "snapshot" }
        val second = shared.collect(initial) { collections++; "again" }

        assertEquals("snapshot", first)
        assertEquals("snapshot", second)
        assertEquals(1, collections)
    }

    @Test
    fun `a new scan always collects afresh even within the same millisecond`() = runTest {
        shared.collect(initial) { "earlier scan" }
        assertEquals("later scan", shared.collect(ScanEpoch.begin(initial.startedNanos)) { "later scan" })
    }

    @Test
    fun `late LSPosed request in the same scan reuses SELinux result even after newer timestamps`() = runTest {
        var collections = 0
        val selinux = shared.collect(initial) { collections++; "parent 23823" }
        // Old comparison (collectedAt >= detectorStartedAt) re-bound because LSPosed starts later.
        val lsposed = shared.collect(initial) { collections++; "different parent" }
        assertEquals(selinux, lsposed)
        assertEquals(1, collections)
    }

    @Test
    fun `a detector waits for the collection in progress and takes it`() = runTest {
        val collectionDone = CompletableDeferred<Unit>()
        var collections = 0
        val first = async {
            shared.collect(initial) {
                collections++
                collectionDone.await()
                "snapshot"
            }
        }
        val second = async { shared.collect(initial) { collections++; "again" } }
        runCurrent()
        collectionDone.complete(Unit)

        assertEquals("snapshot", first.await())
        assertEquals("snapshot", second.await())
        assertEquals(1, collections)
    }
}
