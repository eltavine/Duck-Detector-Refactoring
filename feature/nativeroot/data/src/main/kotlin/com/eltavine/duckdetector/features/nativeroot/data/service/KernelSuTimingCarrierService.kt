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
import com.eltavine.duckdetector.features.nativeroot.data.probes.AndroidKernelSuTimingBackend
import com.eltavine.duckdetector.features.nativeroot.data.probes.KernelSuTimingExperiment
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingObservation
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class KernelSuTimingCarrierService : Service() {
    private val cancelled = AtomicBoolean(false)
    private val messenger = Messenger(Handler(Looper.getMainLooper()) { request ->
        if (request.what != COLLECT) return@Handler false
        val reply = request.replyTo ?: return@Handler true
        if (Application.getProcessName() != "$packageName:ksu_timing") {
            send(reply, failure(KernelSuTimingCollection.UNAVAILABLE, "Incorrect carrier process"))
        } else if (!active.compareAndSet(false, true)) {
            send(reply, failure(KernelSuTimingCollection.UNAVAILABLE, "Carrier busy"))
        } else {
            cancelled.set(false)
            val watchdog = watchdogExecutor.schedule({
                if (Application.getProcessName() == "$packageName:ksu_timing") Process.killProcess(Process.myPid())
            }, 45, TimeUnit.SECONDS)
            CoroutineScope(Dispatchers.IO).launch {
                val observation = try {
                    KernelSuTimingExperiment(AndroidKernelSuTimingBackend(this@KernelSuTimingCarrierService))
                        .collect(cancelled::get)
                } catch (failure: Exception) {
                    failure(KernelSuTimingCollection.UNAVAILABLE, PlatformFailureName.describe(failure))
                }
                try { send(reply, observation) }
                finally { watchdog.cancel(false); active.set(false) }
            }
        }
        true
    })

    override fun onBind(intent: Intent): IBinder = messenger.binder
    override fun onUnbind(intent: Intent?): Boolean {
        cancelled.set(true)
        return false
    }

    private fun send(reply: Messenger, observation: KernelSuTimingObservation) {
        val payload = try { KernelSuTimingPayloadCodec.encode(observation) }
        catch (failure: Exception) {
            KernelSuTimingPayloadCodec.encode(failure(KernelSuTimingCollection.PROTOCOL_ERROR,
                "Carrier encoding failed").copy(cleanupCompleted = observation.cleanupCompleted))
        }
        runCatching {
            reply.send(Message.obtain(null, COLLECT).apply {
                data = Bundle().apply { putByteArray(PAYLOAD, payload) }
            })
        }
    }

    private fun failure(state: KernelSuTimingCollection, detail: String) =
        KernelSuTimingObservation(collection = state, detail = detail)

    companion object {
        internal const val COLLECT = 1
        internal const val PAYLOAD = "payload"
        private val active = AtomicBoolean(false)
        private val watchdogExecutor = Executors.newSingleThreadScheduledExecutor { task ->
            Thread(task, "ksu-timing-watchdog").apply { isDaemon = true }
        }
    }
}
