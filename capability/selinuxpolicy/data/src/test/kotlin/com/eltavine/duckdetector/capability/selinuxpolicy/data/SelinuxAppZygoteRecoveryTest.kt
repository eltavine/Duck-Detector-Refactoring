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

import com.eltavine.duckdetector.core.platform.AppZygoteStartGate
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
class SelinuxAppZygoteRecoveryTest {
    private data class Result(val reason: String? = null, val pid: Int? = null)

    private suspend fun recover(
        first: Result,
        awaitRetirement: suspend (Int) -> Boolean,
        retry: suspend () -> Result,
    ): Result = SelinuxAppZygoteRecovery.recover(
        first = first,
        reason = Result::reason,
        parentPid = Result::pid,
        awaitRetirement = awaitRetirement,
        retry = retry,
        failure = { Result(reason = it) },
    )

    @Test fun `fresh payload skips retirement and never rebinds`() = runTest {
        var waits = 0
        var bindings = 0
        val first = Result(pid = 14)
        val result = recover(first, { waits++; true }, { bindings++; Result(pid = 15) })
        assertEquals(first, result)
        assertEquals(0, waits)
        assertEquals(0, bindings)
    }

    @Test fun `stale preload waits for old parent to vanish then accepts a different parent`() = runTest {
        var waitedPid = -1
        var bindings = 0
        val result = recover(Result(SelinuxAppZygoteRecovery.STALE_PRELOAD, 14),
            awaitRetirement = { waitedPid = it; true },
            retry = { bindings++; Result(pid = 15) },
        )
        assertEquals(14, waitedPid)
        assertEquals(1, bindings)
        assertEquals(Result(pid = 15), result)
    }

    @Test fun `missing payload also waits, but a failed replacement remains a failure`() = runTest {
        val first = Result(SelinuxContextValidityCarrierService.PRELOAD_PAYLOAD_UNAVAILABLE, 14)
        val error = Result("App Zygote preload provenance unavailable.", 15)
        assertEquals(error, recover(first, { true }, { error }))
    }

    @Test fun `unknown parent and failed retirement do not attempt another bind`() = runTest {
        var bindings = 0
        val noPid = recover(Result(SelinuxAppZygoteRecovery.STALE_PRELOAD), { true }, {
            bindings++; Result(pid = 16)
        })
        val cannotObserve = recover(Result(SelinuxAppZygoteRecovery.STALE_PRELOAD, 14), { false }, {
            bindings++; Result(pid = 16)
        })
        assertTrue(noPid.reason.orEmpty().contains("PID unavailable"))
        assertTrue(cannotObserve.reason.orEmpty().contains("carrier children did not retire"))
        assertEquals(0, bindings)
    }

    @Test fun `same parent after retirement is rejected even if the payload claims success`() = runTest {
        val result = recover(Result(SelinuxAppZygoteRecovery.STALE_PRELOAD, 14), { true }, {
            Result(pid = 14)
        })
        assertTrue(result.reason.orEmpty().contains("reused after waiting"))
    }

    @Test fun `retry with unknown replacement parent is not accepted`() = runTest {
        val result = recover(Result(SelinuxAppZygoteRecovery.STALE_PRELOAD, 14), { true }, {
            Result()
        })
        assertTrue(result.reason.orEmpty().contains("Replacement App Zygote parent PID unavailable"))
    }

    @Test fun `a failed replacement binding keeps its real timeout error`() = runTest {
        val timedOut = Result(reason = "SELinux carrier recovery binding timed out.")
        val result = recover(Result(SelinuxAppZygoteRecovery.STALE_PRELOAD, 14), { true }, {
            timedOut
        })
        assertEquals(timedOut, result)
    }

    @Test fun `retirement waits for active children and prevents new binds until the quiet window ends`() = runTest {
        val gate = AppZygoteStartGate(clock = { testScheduler.currentTime })
        val activeThroneHuntChild = gate.acquireLease()
        val retirementStarted = CompletableDeferred<Unit>()
        val recovering = async {
            gate.withExclusive {
                retirementStarted.complete(Unit)
                recover(
                    first = Result(SelinuxAppZygoteRecovery.STALE_PRELOAD, 14),
                    awaitRetirement = { _ ->
                        val childrenRetired = gate.awaitNoActiveLeases(timeoutMs = 5_000L)
                        if (childrenRetired) delay(6_000L)
                        childrenRetired
                    },
                    retry = {
                        gate.admitExclusive(
                            scanStartedAt = 0L,
                            refused = { Result("blocked") },
                            stoppedBeforeConnecting = { false },
                        ) { Result(pid = 15) }
                    },
                )
            }
        }
        retirementStarted.await()
        var competingStarts = 0
        val competing = async {
            gate.admit(
                scanStartedAt = 0L, refused = { Result("blocked") },
                stoppedBeforeConnecting = { false },
            ) {
                competingStarts++
                Result(pid = 15)
            }
        }
        runCurrent()
        assertEquals(0, competingStarts)
        assertFalse(competing.isCompleted)

        // A previously connected carrier can finish and die without acquiring the admission gate.
        activeThroneHuntChild.close()
        assertEquals(Result(pid = 15), recovering.await())
        assertEquals(Result(pid = 15), competing.await())
        assertEquals(1, competingStarts)
    }

    @Test fun `freshness compares preload start with scan start rather than only the APK path`() {
        val old = SelinuxCarrierProvenance(14, 10000, 123_000_000L, "/data/app/same/base.apk")
        assertTrue(SelinuxAppZygoteRecovery.stale(old, scanStartedNanos = 124_000_000L))
        assertFalse(SelinuxAppZygoteRecovery.stale(old, scanStartedNanos = 123_000_000L))
        assertFalse(SelinuxAppZygoteRecovery.stale(null, scanStartedNanos = 124_000_000L))
    }

    @Test fun `preload one nanosecond before the scan within the same millisecond is stale`() {
        val old = SelinuxCarrierProvenance(14, 10000, 123_123_456L, "/data/app/same/base.apk")
        assertTrue(SelinuxAppZygoteRecovery.stale(old, scanStartedNanos = 123_123_457L))
        assertFalse(SelinuxAppZygoteRecovery.stale(old, scanStartedNanos = 123_123_456L))
    }
}
