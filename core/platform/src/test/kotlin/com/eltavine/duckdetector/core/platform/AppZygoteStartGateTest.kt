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

package com.eltavine.duckdetector.core.platform

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AppZygoteStartGateTest {

    private var now = 0L
    private val gate = AppZygoteStartGate(clock = { now })

    @Test
    fun `a start stopped before connecting turns the rest of that scan away`() = runTest {
        now = 105
        assertEquals(STOPPED, admit(scanStartedAt = 100) { STOPPED })

        var attempted = false
        val second = admit(scanStartedAt = 100) {
            attempted = true
            "connected"
        }

        assertEquals(REFUSED, second)
        assertFalse(attempted)
    }

    @Test
    fun `a scan that starts after the failure attempts again`() = runTest {
        now = 105
        admit(scanStartedAt = 100) { STOPPED }

        now = 210
        assertEquals("connected", admit(scanStartedAt = 200) { "connected" })
    }

    @Test
    fun `a start that connected turns nobody away`() = runTest {
        now = 105
        admit(scanStartedAt = 100) { "first" }

        assertEquals("second", admit(scanStartedAt = 100) { "second" })
    }

    @Test
    fun `a start waits for the one in progress and is refused if that one failed`() = runTest {
        val firstStop = CompletableDeferred<Unit>()
        var secondAttempted = false
        now = 105

        val first = async {
            admit(scanStartedAt = 100) {
                firstStop.await()
                STOPPED
            }
        }
        val second = async {
            admit(scanStartedAt = 100) {
                secondAttempted = true
                "connected"
            }
        }
        runCurrent()
        assertFalse(secondAttempted)

        firstStop.complete(Unit)

        assertEquals(STOPPED, first.await())
        assertEquals(REFUSED, second.await())
        assertFalse(secondAttempted)
    }

    @Test
    fun `a start waits for the one in progress and runs if that one connected`() = runTest {
        val firstConnect = CompletableDeferred<Unit>()
        var secondAttempted = false
        now = 105

        val first = async {
            admit(scanStartedAt = 100) {
                firstConnect.await()
                "first"
            }
        }
        val second = async {
            admit(scanStartedAt = 100) {
                secondAttempted = true
                "second"
            }
        }
        runCurrent()
        assertFalse(secondAttempted)

        firstConnect.complete(Unit)

        assertEquals("first", first.await())
        assertEquals("second", second.await())
        assertTrue(secondAttempted)
    }

    @Test
    fun `a lease remains active until closed and close is idempotent`() = runTest {
        val lease = gate.acquireLease()

        assertFalse(gate.awaitNoActiveLeases(timeoutMs = 100L))

        lease.close()
        lease.close()

        assertTrue(gate.awaitNoActiveLeases(timeoutMs = 100L))
    }

    @Test
    fun `a binding failure before Binder attachment releases its lease`() = runTest {
        val carrierLease = AppZygoteCarrierLease(gate)

        assertFalse(gate.awaitNoActiveLeases(timeoutMs = 100L))
        carrierLease.bindingFailed()

        assertTrue(gate.awaitNoActiveLeases(timeoutMs = 100L))
    }

    @Test
    fun `retirement blocks new binds but lets an existing child release its lease`() = runTest {
        val existingChild = gate.acquireLease()
        val retirementEntered = CompletableDeferred<Unit>()
        val retirement = async {
            gate.withExclusive {
                retirementEntered.complete(Unit)
                assertTrue(gate.awaitNoActiveLeases(timeoutMs = 5_000L))
                delay(6_000L)
                gate.admitExclusive(
                    scanStartedAt = 0L,
                    refused = { REFUSED },
                    stoppedBeforeConnecting = { it == STOPPED },
                ) { "replacement" }
            }
        }

        retirementEntered.await()
        var competingStarts = 0
        val competing = async {
            admit(scanStartedAt = 0L) {
                competingStarts++
                "competing"
            }
        }
        runCurrent()
        assertEquals(0, competingStarts)
        assertFalse(competing.isCompleted)

        // Existing connections do not need the admission lock to finish and release their lease.
        existingChild.close()

        assertEquals("replacement", retirement.await())
        assertEquals("competing", competing.await())
        assertEquals(1, competingStarts)
        assertTrue(gate.awaitNoActiveLeases(timeoutMs = 100L))
    }

    private suspend fun admit(scanStartedAt: Long, attempt: suspend () -> String): String =
        gate.admit(
            scanStartedAt = scanStartedAt,
            refused = { REFUSED },
            stoppedBeforeConnecting = { result -> result == STOPPED },
            attempt = attempt,
        )

    private companion object {
        const val STOPPED = "stopped before connecting"
        const val REFUSED = "refused"
    }
}
