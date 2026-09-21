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

package com.eltavine.duckdetector.core.native

import kotlinx.coroutines.test.runTest
import kotlin.coroutines.cancellation.CancellationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class NativeSnapshotCollectorTest {

    private data class Snapshot(
        val payload: String = "",
        val collection: NativeCollectionStatus = NativeCollectionStatus.Collected,
    )

    private class FakeLibrary(
        override val isLoaded: Boolean,
        override val loadFailureDetail: String = "",
    ) : NativeLibraryHandle

    private val loaded = NativeSnapshotCollector(FakeLibrary(isLoaded = true))

    @Test
    fun `reports the parsed snapshot when the bridge succeeds`() {
        val snapshot = loaded.collect(
            readPayload = { "AVAILABLE=1" },
            parse = { Snapshot(payload = it) },
            unavailable = { status -> Snapshot(collection = status) },
        )

        assertEquals("AVAILABLE=1", snapshot.payload)
        assertEquals(NativeCollectionOutcome.COLLECTED, snapshot.collection.outcome)
        assertTrue(snapshot.collection.isTrustworthy)
    }

    @Test
    fun `never calls the bridge when the library is missing`() {
        var bridgeCalled = false
        val collector = NativeSnapshotCollector(
            FakeLibrary(isLoaded = false, loadFailureDetail = "dlopen failed"),
        )

        val snapshot = collector.collect(
            readPayload = { bridgeCalled = true; "AVAILABLE=1" },
            parse = { Snapshot(payload = it) },
            unavailable = { status -> Snapshot(collection = status) },
        )

        assertFalse(bridgeCalled)
        assertEquals(NativeCollectionOutcome.LIBRARY_UNAVAILABLE, snapshot.collection.outcome)
        assertEquals("dlopen failed", snapshot.collection.detail)
        assertFalse(snapshot.collection.isTrustworthy)
    }

    @Test
    fun `separates a throwing bridge from a rejected payload`() {
        val bridgeFailure = loaded.collect(
            readPayload = { throw IllegalStateException("probe aborted") },
            parse = { Snapshot(payload = it) },
            unavailable = { status -> Snapshot(collection = status) },
        )
        val parseFailure = loaded.collect(
            readPayload = { "not a payload" },
            parse = { throw NumberFormatException("bad column") },
            unavailable = { status -> Snapshot(collection = status) },
        )

        assertEquals(NativeCollectionOutcome.BRIDGE_FAILED, bridgeFailure.collection.outcome)
        assertEquals(NativeCollectionOutcome.PAYLOAD_REJECTED, parseFailure.collection.outcome)
    }

    @Test
    fun `keeps the failure cause in the auditable detail`() {
        val snapshot = loaded.collect(
            readPayload = { throw IllegalStateException("probe aborted") },
            parse = { Snapshot(payload = it) },
            unavailable = { status -> Snapshot(collection = status) },
        )

        assertNotNull(snapshot.collection.detail)
        assertTrue(snapshot.collection.detail.contains("IllegalStateException"))
        assertTrue(snapshot.collection.detail.contains("probe aborted"))
    }

    @Test
    fun `survives an UnsatisfiedLinkError rather than propagating it`() {
        // The unresolved-symbol case is an Error, not an Exception, so a plain `catch (Exception)`
        // guard would let it escape into the scan coroutine.
        val snapshot = loaded.collect(
            readPayload = { throw UnsatisfiedLinkError("nativeCollectSnapshot") },
            parse = { Snapshot(payload = it) },
            unavailable = { status -> Snapshot(collection = status) },
        )

        assertEquals(NativeCollectionOutcome.BRIDGE_FAILED, snapshot.collection.outcome)
    }

    @Test
    fun `rethrows cancellation so a cancelled scan still unwinds`() = runTest {
        try {
            loaded.collect(
                readPayload = { throw CancellationException("scan cancelled") },
                parse = { Snapshot(payload = it) },
                unavailable = { status -> Snapshot(collection = status) },
            )
            fail("Cancellation must not be recorded as a probe failure.")
        } catch (expected: CancellationException) {
            assertEquals("scan cancelled", expected.message)
        }
    }
}
