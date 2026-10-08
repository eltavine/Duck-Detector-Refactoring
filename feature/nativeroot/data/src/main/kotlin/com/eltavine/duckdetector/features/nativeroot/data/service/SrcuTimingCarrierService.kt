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

package com.eltavine.duckdetector.features.nativeroot.data.service

import android.app.Application
import android.app.Service
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.Process
import com.eltavine.duckdetector.core.platform.PlatformFailureName
import com.eltavine.duckdetector.features.nativeroot.data.probes.SrcuTimingExperiment
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingObservation
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/** One-way request/reply: the host never blocks inside a synchronous remote Binder transaction. */
class SrcuTimingCarrierService : Service() {
    private val cancelled = AtomicBoolean(false)
    private val handler = Handler(Looper.getMainLooper())
    private val watchdog = Runnable {
        // A syscall sleeping in the kernel may survive SIGKILL. This bounds user-space waiting,
        // not kernel recovery or cleanup. Only this feature's declared private process is killed.
        if (Application.getProcessName() == "$packageName:srcu_timing") Process.killProcess(Process.myPid())
    }
    private val messenger = Messenger(Handler(Looper.getMainLooper()) { request ->
        if (request.what != COLLECT) return@Handler false
        val reply = request.replyTo ?: return@Handler true
        if (Application.getProcessName() != "$packageName:srcu_timing") {
            send(reply, SrcuTimingObservation(SrcuTimingCollection.IPC_FAILED,
                failureDetail = "The carrier must run in its declared private process"))
        } else if (!active.compareAndSet(false, true)) {
            send(reply, SrcuTimingObservation(SrcuTimingCollection.BUSY))
        } else {
            cancelled.set(false)
            handler.postDelayed(watchdog, WATCHDOG_MS)
            CoroutineScope(Dispatchers.IO).launch {
                val result = try {
                    SrcuTimingExperiment(this@SrcuTimingCarrierService).collect(cancelled::get)
                } catch (failure: Exception) {
                    SrcuTimingObservation(SrcuTimingCollection.NATIVE_FAILED,
                        failureDetail = PlatformFailureName.describe(failure))
                }
                handler.post {
                    handler.removeCallbacks(watchdog)
                    active.set(false)
                    send(reply, result)
                }
            }
        }
        true
    })

    override fun onBind(intent: Intent): IBinder = messenger.binder
    override fun onUnbind(intent: Intent?): Boolean {
        cancelled.set(true)
        return false
    }

    private fun send(reply: Messenger, observation: SrcuTimingObservation) {
        val payload = try { SrcuTimingPayloadCodec.encode(observation) } catch (failure: Exception) {
            SrcuTimingPayloadCodec.encode(SrcuTimingObservation(SrcuTimingCollection.IPC_FAILED,
                failureDetail = PlatformFailureName.describe(failure),
                cleanupCompleted = observation.cleanupCompleted))
        }
        runCatching {
            reply.send(Message.obtain(null, COLLECT).apply {
                data = Bundle().apply { putString(PAYLOAD, payload) }
            })
        }
    }

    companion object {
        internal const val COLLECT = 1
        internal const val PAYLOAD = "payload"
        private const val WATCHDOG_MS = 25_000L

        // A run outlives its service instance: after an unbind, the next bind creates a new instance
        // in this process while the old run is still finishing, so admission is process-wide.
        // Cancellation stays per instance, because each run reads the flag its own unbind set.
        private val active = AtomicBoolean(false)
    }
}
