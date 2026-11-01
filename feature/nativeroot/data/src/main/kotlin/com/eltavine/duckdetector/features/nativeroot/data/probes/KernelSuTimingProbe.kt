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

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import com.eltavine.duckdetector.core.platform.PlatformFailureName
import com.eltavine.duckdetector.features.nativeroot.data.service.KernelSuTimingCarrierService
import com.eltavine.duckdetector.features.nativeroot.data.service.KernelSuTimingPayloadCodec
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingObservation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withTimeoutOrNull

class KernelSuTimingProbe(private val context: Context?) {
    suspend fun collect(): KernelSuTimingObservation {
        val app = context?.applicationContext ?: return failure(KernelSuTimingCollection.UNAVAILABLE, "Context unavailable")
        if (!admission.tryLock()) return failure(KernelSuTimingCollection.UNAVAILABLE, "Timing method busy")
        try { return collectRemote(app) }
        finally { admission.unlock() }
    }

    private suspend fun collectRemote(app: Context): KernelSuTimingObservation {
        val result = CompletableDeferred<KernelSuTimingObservation>()
        val reply = Messenger(Handler(Looper.getMainLooper()) { message ->
            try {
                require(message.what == KernelSuTimingCarrierService.COLLECT)
                val payload = requireNotNull(message.data.getByteArray(KernelSuTimingCarrierService.PAYLOAD))
                result.complete(KernelSuTimingPayloadCodec.decode(payload))
            } catch (failure: Exception) {
                result.complete(failure(KernelSuTimingCollection.PROTOCOL_ERROR, "Invalid carrier reply"))
            }
            true
        })
        fun failed(state: KernelSuTimingCollection, detail: String) { result.complete(failure(state, detail)) }
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                try {
                    Messenger(requireNotNull(service)).send(Message.obtain(null, KernelSuTimingCarrierService.COLLECT).apply {
                        replyTo = reply
                    })
                } catch (failure: Exception) { failed(KernelSuTimingCollection.UNAVAILABLE, "Carrier request failed") }
            }
            override fun onNullBinding(name: ComponentName?) { failed(KernelSuTimingCollection.UNAVAILABLE, "Null carrier binding") }
            override fun onBindingDied(name: ComponentName?) { failed(KernelSuTimingCollection.WORKER_DIED, "Carrier binding died; cleanup unconfirmed") }
            override fun onServiceDisconnected(name: ComponentName?) {
                failed(KernelSuTimingCollection.WORKER_DIED, "Carrier disconnected; cause and cleanup unknown")
            }
        }
        var bound = false
        try {
            bound = app.bindService(Intent(app, KernelSuTimingCarrierService::class.java), connection, Context.BIND_AUTO_CREATE)
            if (!bound) return failure(KernelSuTimingCollection.UNAVAILABLE, "Carrier bind rejected")
            return withTimeoutOrNull(50_000) { result.await() }
                ?: failure(KernelSuTimingCollection.TIMED_OUT, "Host deadline exceeded; cleanup unconfirmed")
        } catch (failure: Exception) {
            if (failure is CancellationException) throw failure
            return failure(KernelSuTimingCollection.UNAVAILABLE, PlatformFailureName.describe(failure))
        } finally {
            result.cancel()
            if (bound) runCatching { app.unbindService(connection) }
        }
    }

    private fun failure(state: KernelSuTimingCollection, detail: String) =
        KernelSuTimingObservation(collection = state, detail = detail)
    companion object { private val admission = Mutex() }
}
