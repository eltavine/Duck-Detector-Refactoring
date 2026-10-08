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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import android.content.Context
import android.os.Build
import android.system.Os
import com.eltavine.duckdetector.core.platform.PlatformFailureName
import com.eltavine.duckdetector.features.nativeroot.data.native.SrcuTimingNativeBridge
import com.eltavine.duckdetector.features.nativeroot.domain.ROUND_COUNT
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingObservation
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingRound
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingWindow
import kotlin.random.Random

/** Runs only in the private same-UID carrier, under its independent process watchdog. */
internal class SrcuTimingExperiment(private val context: Context) {
    fun collect(cancelled: () -> Boolean): SrcuTimingObservation {
        val kernel = Os.uname().release
        srcuTimingApplicability(Build.VERSION.SDK_INT, kernel)?.let {
            return SrcuTimingObservation(it, kernelRelease = kernel)
        }
        val stimulus = SrcuPermissionStimulus(context)
        try { stimulus.verifyUnusedName() } catch (failure: Exception) {
            return SrcuTimingObservation(SrcuTimingCollection.PERMISSION_TREE_UNAVAILABLE,
                kernelRelease = kernel, failureDetail = PlatformFailureName.describe(failure))
        }
        val bridge = SrcuTimingNativeBridge()
        val directory = context.cacheDir.resolve("srcu-timing")
        val rounds = mutableListOf<SrcuTimingRound>()
        var collection = SrcuTimingCollection.COLLECTED
        var detail = ""
        var cleanupCompleted = false
        var triggerFailure: Exception? = null
        var failedWindow: SrcuTimingWindow? = null
        try {
            check(directory.isDirectory || directory.mkdir()) { "Private watch directory unavailable" }
            fun trigger() {
                check(!cancelled()) { "Experiment cancelled" }
                try { stimulus.apply() } catch (failure: Exception) { triggerFailure = failure }
            }
            fun collectWindow(action: () -> Unit): SrcuTimingWindow {
                val window = bridge.measure(directory.absolutePath, Runnable(action))
                triggerFailure?.let { failedWindow = window; throw it }
                if (window.beginNanos <= 0 || window.endNanos <= window.beginNanos ||
                    window.samples.isEmpty() || window.samples.any { !it.usable }) {
                    failedWindow = window
                    error("Incomplete native window")
                }
                return window
            }
            // Warm up JNI, storage and permission registration outside the scored rounds.
            val warmup = collectWindow(::trigger)
            var duration = (warmup.endNanos - warmup.beginNanos).coerceIn(20_000_000, 500_000_000)
            repeat(ROUND_COUNT) {
                check(!cancelled()) { "Experiment cancelled" }
                var idle: SrcuTimingWindow? = null
                var stimulated: SrcuTimingWindow? = null
                var sequential: SrcuTimingWindow? = null
                for (arm in listOf(0, 1, 2).shuffled(Random.Default)) {
                    // Finite washout separates us from the preceding rewrite; it cannot prove the
                    // global fsnotify domain is idle. Sequential controls test that limitation.
                    Thread.sleep(25)
                    val window = when (arm) {
                        1 -> collectWindow(::trigger)
                        2 -> {
                            trigger()
                            triggerFailure?.let { throw it }
                            collectWindow { sleepNanos(duration) }
                        }
                        else -> collectWindow { sleepNanos(duration) }
                    }
                    when (arm) { 0 -> idle = window; 1 -> stimulated = window; 2 -> sequential = window }
                }
                rounds += SrcuTimingRound(requireNotNull(idle), requireNotNull(stimulated), requireNotNull(sequential))
                duration = (requireNotNull(stimulated).endNanos - stimulated.beginNanos)
                    .coerceIn(20_000_000, 500_000_000)
            }
        } catch (failure: Exception) {
            collection = when {
                triggerFailure is SecurityException -> SrcuTimingCollection.PERMISSION_TREE_UNAVAILABLE
                triggerFailure != null -> SrcuTimingCollection.TRIGGER_FAILED
                else -> SrcuTimingCollection.NATIVE_FAILED
            }
            detail = PlatformFailureName.describe(failure)
        } catch (failure: LinkageError) {
            collection = SrcuTimingCollection.NATIVE_FAILED
            detail = PlatformFailureName.describe(failure)
        } finally {
            try {
                stimulus.cleanup()
                cleanupCompleted = true
            } catch (failure: Exception) {
                collection = SrcuTimingCollection.CLEANUP_FAILED
                detail += "\n" + PlatformFailureName.describe(failure)
            }
            directory.delete()
        }
        return SrcuTimingObservation(collection, rounds, kernel, detail, cleanupCompleted, failedWindow)
    }

    private fun sleepNanos(nanos: Long) {
        Thread.sleep(nanos / 1_000_000, (nanos % 1_000_000).toInt())
    }
}
