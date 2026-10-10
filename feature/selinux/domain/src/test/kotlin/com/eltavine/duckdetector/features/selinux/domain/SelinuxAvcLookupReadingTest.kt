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

package com.eltavine.duckdetector.features.selinux.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxAvcLookupReadingTest {
    @Test fun `each band needs every round and allows only a tenth of extra activity`() {
        val one = listOf(4096L, 4102L, 4505L, 4100L)
        val two = listOf(8192L, 8198L, 8601L, 8200L)
        assertEquals(SelinuxAvcLookupProfile.ONE_ONE, reading(one, one).profile)
        assertEquals(SelinuxAvcLookupProfile.ONE_TWO, reading(one, two).profile)
        assertEquals(SelinuxAvcLookupProfile.TWO_TWO, reading(two, two).profile)
        listOf(
            one.dropLast(1) + 4506L to one,
            one.dropLast(1) + 4095L to one,
            one to two.dropLast(1) + 8602L,
            one to two.dropLast(1) + 8191L,
            one.dropLast(1) + 8198L to one,
            two to one,
            one to one.dropLast(1),
            emptyList<Long>() to emptyList(),
        ).forEach { (a, b) -> assertEquals("$a / $b", SelinuxAvcLookupProfile.UNCLASSIFIED, reading(a, b).profile) }
        assertEquals(SelinuxAvcLookupProfile.UNCLASSIFIED, reading(one, two, writes = 0).profile)
    }

    @Test fun `only an extra lookup is flagged and nothing raises the status`() {
        val one = List(4) { 4102L }
        val two = List(4) { 8198L }
        assertTrue(reading(one, two).extraLookupObserved)
        assertTrue(reading(two, two).extraLookupObserved)
        assertFalse(reading(one, one).extraLookupObserved)
        assertFalse(reading(one, two.dropLast(1) + 9000L).extraLookupObserved)
        listOf(reading(one, two), reading(one, one), reading(one, two, SelinuxAvcLookupCollection.PERMISSION_LIMITED))
            .forEach { assertEquals(DetectorStatus.info(InfoKind.SUPPORT), it.status) }
        assertEquals(SelinuxAvcLookupProfile.ONE_TWO.label, reading(one, two).label)
        assertEquals(4102.0 / 4096, reading(one, two).rateA!!, 1e-9)
        assertEquals(8198.0 / 4096, reading(one, two).rateB!!, 1e-9)
    }

    @Test fun `uncollected counts are never classified even when they look like a profile`() {
        val one = List(4) { 4102L }
        val two = List(4) { 8198L }
        SelinuxAvcLookupCollection.entries.filter { it != SelinuxAvcLookupCollection.COLLECTED }.forEach { collection ->
            val reading = reading(one, two, collection)
            assertNull(reading.profile)
            assertFalse(reading.extraLookupObserved)
            assertNull(reading.rateA)
            assertEquals(collection.label, reading.label)
        }
    }

    private fun reading(
        a: List<Long>,
        b: List<Long>,
        collection: SelinuxAvcLookupCollection = SelinuxAvcLookupCollection.COLLECTED,
        writes: Int = 4096,
    ) = SelinuxAvcLookupReading(
        collection = collection, writesPerBatch = writes, batchesA = a, batchesB = b, completedRounds = a.size,
        pairs = 128, medianANs = 301, medianBNs = 201, medianDeltaNs = 100,
        details = SelinuxAvcLookupCollectionDetails(
            step = "FINISHED", errno = 0, unexpectedWrite = null, identityChanged = false, childEnd = "EXITED",
            childExitStatus = 0, childSignal = 0, childErrno = 0, cpu = 2, cpuRow = 2, cpuRows = 8, possibleCpus = 8,
            failureReason = null,
        ),
    )
}
