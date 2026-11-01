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

package com.eltavine.duckdetector

import android.os.SystemClock
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.eltavine.duckdetector.core.evidence.ScanEpoch
import com.eltavine.duckdetector.core.platform.AppZygoteStartGate
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxAppZygoteLifecycleProbe
import com.eltavine.duckdetector.features.nativeroot.data.service.ThroneHuntCarrierManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Exercises real useAppZygote bindings and delayed retirement on an Android device/AVD. */
@RunWith(AndroidJUnit4::class)
class AppZygoteLifecycleRuntimeTest {

    @Test
    fun stalePreloadWaitsForLongLivedCarrierThenRebindsToANewGeneration() =
        runBlocking(Dispatchers.IO) {
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val gate = AppZygoteStartGate.Default
            val throneHunt = ThroneHuntCarrierManager(context)

            try {
                val heldState = throneHunt.collectSnapshot(SystemClock.elapsedRealtime())
                Log.i(TAG, "held ThroneHunt carrier failure=${heldState.failureReason} " +
                    "watchInstalled=${heldState.watchInstalled}")
                assertFalse(
                    "ThroneHunt did not retain a live App-Zygote child lease",
                    gate.awaitNoActiveLeases(timeoutMs = 500L),
                )

                val selinux = SelinuxAppZygoteLifecycleProbe(context)
                val scan = ScanEpoch.begin(SystemClock.elapsedRealtimeNanos())
                val recovery = async(Dispatchers.IO) { selinux.collect(scan.startedNanos) }

                // The stale SELinux result must not bypass the still-connected ThroneHunt child.
                delay(1_000L)
                assertFalse(
                    "stale recovery completed while another App-Zygote child was still connected",
                    recovery.isCompleted,
                )

                throneHunt.close()
                val replacement = withTimeout(55_000L) { recovery.await() }
                Log.i(TAG, "replacement SELinux snapshot available=${replacement.available} " +
                    "failure=${replacement.failureReason}")

                assertNotEquals(
                    "Recovery returned the stale preload unchanged",
                    "App Zygote preload belongs to an earlier scan.",
                    replacement.failureReason,
                )
                assertFalse(
                    "Recovery accepted a reused App-Zygote parent: ${replacement.failureReason}",
                    replacement.failureReason.orEmpty().contains("reused after waiting"),
                )
                assertFalse(
                    "Recovery did not retire tracked App-Zygote children: ${replacement.failureReason}",
                    replacement.failureReason.orEmpty().contains("carrier children did not retire"),
                )
                assertTrue(
                    "Carrier Binder death was not observed after retirement",
                    gate.awaitNoActiveLeases(timeoutMs = 15_000L),
                )

                val acceptedParentPid = requireNotNull(replacement.appZygoteParentPid) {
                    "Fresh carrier did not report its App-Zygote parent PID"
                }
                assertEquals(
                    "Preload version code was not captured from the actual App-Zygote build",
                    com.eltavine.duckdetector.sdk.BuildConfig.PRELOAD_VERSION_CODE.toLong(),
                    replacement.preloadVersionCode,
                )
                assertEquals(
                    "Preload build revision was not captured from the actual App-Zygote build",
                    com.eltavine.duckdetector.sdk.BuildConfig.PRELOAD_BUILD_REVISION,
                    replacement.preloadBuildRevision,
                )
                // Backdate the logical scan deliberately: timestamp-only freshness would accept
                // this still-live generation, so this assertion specifically exercises the
                // persistent generation fence across manager instances.
                val acceptedPreloadStartedNanos = requireNotNull(replacement.preloadStartedNanos) {
                    "Fresh carrier did not report its preload timestamp"
                }
                // Start one nanosecond before the exact preload timestamp. The generation would
                // pass the timestamp check, so only the persistent consumed-generation fence can
                // force retirement and prevent reuse of the same parent.
                val replayScan = ScanEpoch.begin(acceptedPreloadStartedNanos - 1L)
                val restartedProbe = SelinuxAppZygoteLifecycleProbe(context)
                val replay = withTimeout(55_000L) { restartedProbe.collect(replayScan.startedNanos) }
                Log.i(TAG, "replay fence result available=${replay.available} " +
                    "parentPid=${replay.appZygoteParentPid} failure=${replay.failureReason}")
                assertTrue("Replay recovery did not produce an available snapshot: ${replay.failureReason}",
                    replay.available)
                assertEquals(replacement.preloadVersionCode, replay.preloadVersionCode)
                assertEquals(replacement.preloadBuildRevision, replay.preloadBuildRevision)
                assertTrue(
                    "Generation-fence replay test did not actually predate the original preload",
                    acceptedPreloadStartedNanos > replayScan.startedNanos,
                )
                assertNotEquals(
                    "A previously accepted preload generation was replayed after a new manager instance",
                    acceptedParentPid,
                    replay.appZygoteParentPid,
                )
            } finally {
                throneHunt.close()
            }
        }

    private companion object {
        const val TAG = "DuckAppZygoteLifecycleTest"
    }
}
