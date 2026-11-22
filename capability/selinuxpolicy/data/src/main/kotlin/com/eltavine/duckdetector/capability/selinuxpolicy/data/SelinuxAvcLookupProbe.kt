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

import android.system.Os
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector

private val kernelVersionPrefix = Regex("""^([0-9]+)\.([0-9]+)(?=[.-]|$)""")

private fun currentKernelRelease(): String? = runCatching { Os.uname().release }.getOrNull()

/** The parent timing experiment requires Linux 5.10 or newer. */
public fun isAppZygoteParentTimingKernelEnabled(kernelRelease: String? = currentKernelRelease()): Boolean {
    val version = kernelVersionPrefix.find(kernelRelease.orEmpty()) ?: return true
    val major = version.groupValues[1].toIntOrNull() ?: return true
    val minor = version.groupValues[2].toIntOrNull() ?: return true
    return major > 5 || (major == 5 && minor >= 10)
}

/** Runs an isolated B/A preflight, then the PoC parent timing, before costly AVC collection. */
internal class SelinuxAvcLookupProbe(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
    private val kernelRelease: () -> String? = ::currentKernelRelease,
) {
    fun inspect(trace: (String) -> Unit = {}): SelinuxAvcLookupSnapshot {
        val earlyParent = if (isAppZygoteParentTimingKernelEnabled(kernelRelease())) {
            // JNI forks a lightweight safety-check child before touching the live carrier.
            // Running 33k AVC writes first perturbs the scheduler and invalidates PoC parity.
            trace("AVC lightweight parent timing preflight begin")
            collector.collect(
                readPayload = ::nativeCollectParentTiming,
                parse = { it },
                unavailable = { "" },
            )
        } else {
            trace("AVC parent timing skipped on Linux older than 5.10")
            ""
        }
        trace("AVC disposable child begin")
        val child = collector.collect(
            readPayload = ::nativeCollectAvcLookup,
            parse = SelinuxAvcLookupPayloadCodec::decode,
            unavailable = { failure ->
                SelinuxAvcLookupSnapshot(
                    state = SelinuxAvcLookupState.UNAVAILABLE,
                    failureReason = failure.explain("App zygote AVC lookup experiment was unavailable"),
                )
            },
        )
        trace("AVC child returned state=${child.state} step=${child.step} errno=${child.errno} " +
            "end=${child.childEnd} exit=${child.childExitStatus} signal=${child.childSignal} " +
            "pid=${child.pid} cpu=${child.cpu} pairs=${child.pairs} migrations=${child.cpuMigrations} " +
            "medians=${child.timingMediansAvailable}")
        val result = withParentTiming(child, earlyParent)
        trace("AVC preload parent returned attempted=${result.parentTiming.attempted} " +
            "complete=${result.parentTiming.complete} errno=${result.parentTiming.error}")
        return result
    }

    internal fun withParentTiming(
        child: SelinuxAvcLookupSnapshot,
        parentPayload: String,
    ): SelinuxAvcLookupSnapshot {
        // This only attaches an existing payload; it never replays parent syscalls
        // after a failed child or loses a completed parent sample to optional counters.
        return child.copy(parentTiming = SelinuxAvcLookupPayloadCodec.decodeParent(parentPayload))
    }

    private external fun nativeCollectAvcLookup(): String
    private external fun nativeCollectParentTiming(): String
}
