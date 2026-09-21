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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Covers the two pieces of this type that every detector depends on: whether a snapshot may be read
 * as evidence, and the single wording rule used for the report line when it may not.
 */
class NativeCollectionStatusTest {

    @Test
    fun `only collected snapshots are trustworthy`() {
        assertTrue(NativeCollectionStatus.Collected.isTrustworthy)
        NativeCollectionOutcome.entries
            .filter { it != NativeCollectionOutcome.COLLECTED }
            .forEach { outcome ->
                assertFalse(outcome.name, NativeCollectionStatus(outcome = outcome).isTrustworthy)
            }
    }

    @Test
    fun `failed keeps the exception type and message apart`() {
        val status = NativeCollectionStatus.failed(
            outcome = NativeCollectionOutcome.BRIDGE_FAILED,
            cause = IllegalStateException("probe aborted"),
        )

        assertEquals(NativeCollectionOutcome.BRIDGE_FAILED, status.outcome)
        assertEquals("IllegalStateException: probe aborted", status.detail)
    }

    @Test
    fun `failed names a messageless cause only once`() {
        // UnsatisfiedLinkError frequently arrives with a null message. Repeating the type as its own
        // description would put "UnsatisfiedLinkError: UnsatisfiedLinkError" into the report.
        val status = NativeCollectionStatus.failed(
            outcome = NativeCollectionOutcome.LIBRARY_UNAVAILABLE,
            cause = UnsatisfiedLinkError(),
        )

        assertEquals("UnsatisfiedLinkError", status.detail)
    }

    @Test
    fun `failed ignores a blank message`() {
        val status = NativeCollectionStatus.failed(
            outcome = NativeCollectionOutcome.PAYLOAD_REJECTED,
            cause = IllegalArgumentException("   "),
        )

        assertEquals("IllegalArgumentException", status.detail)
    }

    @Test
    fun `explain appends the detail when one was captured`() {
        val status = NativeCollectionStatus.failed(
            outcome = NativeCollectionOutcome.LIBRARY_UNAVAILABLE,
            cause = UnsatisfiedLinkError("dlopen failed"),
        )

        assertEquals(
            "Native mount snapshot was unavailable: UnsatisfiedLinkError: dlopen failed",
            status.explain("Native mount snapshot was unavailable"),
        )
    }

    @Test
    fun `explain closes the summary when no detail was captured`() {
        assertEquals(
            "Native mount snapshot was unavailable.",
            NativeCollectionStatus.Collected.explain("Native mount snapshot was unavailable"),
        )
    }
}
