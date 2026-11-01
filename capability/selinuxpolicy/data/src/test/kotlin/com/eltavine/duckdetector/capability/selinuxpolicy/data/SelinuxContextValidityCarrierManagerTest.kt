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
import com.eltavine.duckdetector.core.evidence.ScanEpoch
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.delay
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class SelinuxContextValidityCarrierManagerTest {

    private val origin = SelinuxCarrierProvenance(23823, 10397, 1000L, "/data/app/old/base.apk")
    private val current = SelinuxCarrierExpectedCode(10397, origin.apkPath)

    @Test
    fun `binding and response matching the same generation accepts a preload`() {
        val raw = SelinuxCarrierProvenanceCodec.attach("AVAILABLE=1\n", origin)
        assertNull(SelinuxContextValidityCarrierManager().provenanceFailureReason(raw, current, current, 2000L))
    }

    @Test
    fun `APK update during the Binder call rejects the old result`() {
        val raw = SelinuxCarrierProvenanceCodec.attach("AVAILABLE=1\n", origin)
        val updated = current.copy(apkPath = "/data/app/new/base.apk")
        assertEquals("SELinux carrier APK changed during collection.",
            SelinuxContextValidityCarrierManager().provenanceFailureReason(raw, current, updated, 2000L))
        assertEquals("App Zygote preload APK generation mismatch.",
            SelinuxContextValidityCarrierManager().provenanceFailureReason(raw, updated, updated, 2000L))
    }

    @Test
    fun `unknown APK metadata rejects a seemingly successful carrier`() {
        val raw = SelinuxCarrierProvenanceCodec.attach("AVAILABLE=1\n", origin)
        assertEquals("SELinux carrier APK identity unavailable.",
            SelinuxContextValidityCarrierManager().provenanceFailureReason(raw, null, current, 2000L))
    }

    @Test
    fun `a service failure is retained without accepting provenance-free successful evidence`() {
        val manager = SelinuxContextValidityCarrierManager()
        val failed = SelinuxContextValidityCarrierService.carrierFailurePayload(
            SelinuxContextValidityCarrierService.PRELOAD_PAYLOAD_UNAVAILABLE, "No inherited payload",
        )
        assertEquals(SelinuxContextValidityCarrierService.PRELOAD_PAYLOAD_UNAVAILABLE,
            manager.provenanceFailureReason(failed, current, current, 2000L))
        assertEquals("App Zygote preload provenance unavailable.",
            manager.provenanceFailureReason("AVAILABLE=1\n", current, current, 2000L))
    }

    @Test
    fun `missing preload completes once and never waits for the old zygote`() = runTest {
        var attempts = 0
        val reason = SelinuxContextValidityCarrierManager.boundedSingleAttempt(
            timeoutMs = 15000L,
            onTimeout = { "timed out" },
        ) {
            attempts++
            "Dedicated app_zygote preload payload unavailable."
        }
        assertEquals("Dedicated app_zygote preload payload unavailable.", reason)
        assertEquals(1, attempts)
        assertEquals(0L, testScheduler.currentTime)
    }

    @Test
    fun `a timed-out Binder attempt returns timeout rather than the first failure`() = runTest {
        var attempts = 0
        val result = SelinuxContextValidityCarrierManager.boundedSingleAttempt(
            timeoutMs = 100L,
            onTimeout = { "SELinux carrier probe timed out." },
        ) {
            attempts++
            delay(1000L)
            "connected"
        }
        assertEquals("SELinux carrier probe timed out.", result)
        assertEquals(1, attempts)
        assertEquals(100L, testScheduler.currentTime)
    }

    @Test
    fun `another carrier holding the start gate cannot cause a second SELinux attempt`() = runTest {
        val gate = AppZygoteStartGate(clock = { testScheduler.currentTime })
        val releaseOtherCarrier = CompletableDeferred<Unit>()
        val otherCarrier = async {
            gate.admit(
                scanStartedAt = 0L, refused = { "blocked" },
                stoppedBeforeConnecting = { false },
            ) {
                releaseOtherCarrier.await()
                "other carrier finished"
            }
        }
        runCurrent()
        var attempts = 0
        val selinux = async {
            SelinuxContextValidityCarrierManager.boundedSingleAttempt(
                timeoutMs = 100L, onTimeout = { "timed out" },
            ) {
                gate.admit(
                    scanStartedAt = 0L, refused = { "blocked" },
                    stoppedBeforeConnecting = { false },
                ) {
                    attempts++
                    "collected"
                }
            }
        }
        runCurrent()
        advanceTimeBy(100L)
        runCurrent()
        assertEquals("timed out", selinux.await())
        assertEquals(0, attempts)
        releaseOtherCarrier.complete(Unit)
        assertEquals("other carrier finished", otherCarrier.await())
    }

    @Test
    fun `missing context reports carrier failure across related probes`() = runBlocking {
        val snapshot = SelinuxContextValidityCarrierManager(context = null).collectSnapshot(ScanEpoch.begin(0L))

        assertEquals("SELinux carrier service unavailable.", snapshot.failureReason)
        assertEquals("SELinux carrier service unavailable.", snapshot.procAttrCurrentFailureReason)
        assertEquals("SELinux carrier service unavailable.", snapshot.dirtyPolicyFailureReason)
        assertEquals("SELinux carrier service unavailable.", snapshot.policyloadSeqnoFailureReason)
        assertEquals(SelinuxPolicyloadSeqnoState.UNAVAILABLE.name, snapshot.policyloadSeqnoState)
        assertEquals(SelinuxAvcLookupState.UNAVAILABLE, snapshot.avcLookup.state)
        assertEquals("SELinux carrier service unavailable.", snapshot.avcLookup.failureReason)
    }
}
