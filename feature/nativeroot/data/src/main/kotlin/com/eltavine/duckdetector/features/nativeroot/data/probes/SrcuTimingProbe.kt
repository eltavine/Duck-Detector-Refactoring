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
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.system.Os
import com.eltavine.duckdetector.core.detector.ConsentDecision
import com.eltavine.duckdetector.core.platform.PlatformFailureName
import com.eltavine.duckdetector.features.nativeroot.data.service.SrcuTimingCarrierService
import com.eltavine.duckdetector.features.nativeroot.data.service.SrcuTimingPayloadCodec
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingObservation
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withTimeoutOrNull

class SrcuTimingProbe(private val context: Context?) {
    suspend fun collect(): SrcuTimingObservation = try {
        collectAuthorized()
    } catch (failure: Exception) {
        if (failure is kotlinx.coroutines.CancellationException) throw failure
        failure(PlatformFailureName.describe(failure))
    }

    private suspend fun collectAuthorized(): SrcuTimingObservation {
        val app = context?.applicationContext ?: return failure("Context unavailable")
        if (SrcuTimingConsentStore(app).decision() != ConsentDecision.GRANTED) return SrcuTimingObservation()
        val kernel = Os.uname().release
        srcuTimingApplicability(Build.VERSION.SDK_INT, kernel)?.let {
            return SrcuTimingObservation(it, kernelRelease = kernel)
        }
        if (!admission.tryLock()) return SrcuTimingObservation(SrcuTimingCollection.BUSY, kernelRelease = kernel)
        try { return collectRemote(app).copy(kernelRelease = kernel) }
        finally { admission.unlock() }
    }

    private suspend fun collectRemote(app: Context): SrcuTimingObservation {
        val result = CompletableDeferred<String>()
        fun complete(observation: SrcuTimingObservation) {
            result.complete(SrcuTimingPayloadCodec.encode(observation))
        }
        val bound = AtomicBoolean(false)
        val reply = Messenger(Handler(Looper.getMainLooper()) { message ->
            try {
                result.complete(requireNotNull(message.data.getString(SrcuTimingCarrierService.PAYLOAD)))
            } catch (failure: Exception) { complete(failure(PlatformFailureName.describe(failure))) }
            true
        })
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                try {
                    Messenger(requireNotNull(service)).send(Message.obtain(null, SrcuTimingCarrierService.COLLECT).apply {
                        replyTo = reply
                    })
                } catch (failure: Exception) { complete(failure(PlatformFailureName.describe(failure))) }
            }
            override fun onNullBinding(name: ComponentName?) { complete(failure("Null carrier binding")) }
            override fun onBindingDied(name: ComponentName?) { complete(failure("Carrier binding died")) }
            override fun onServiceDisconnected(name: ComponentName?) {
                complete(SrcuTimingObservation(SrcuTimingCollection.TIMED_OUT,
                    failureDetail = "Carrier disconnected; watchdog or process death, cleanup unconfirmed"))
            }
        }
        try {
            val accepted = app.bindService(Intent(app, SrcuTimingCarrierService::class.java),
                connection, Context.BIND_AUTO_CREATE)
            bound.set(accepted)
            if (!accepted) return failure("Carrier bind rejected")
            return withTimeoutOrNull(30_000) {
                val payload = result.await()
                withContext(Dispatchers.Default) { SrcuTimingPayloadCodec.decode(payload) }
            }
                ?: SrcuTimingObservation(SrcuTimingCollection.TIMED_OUT, failureDetail = "Carrier response deadline exceeded; cleanup unconfirmed")
        } catch (failure: Exception) {
            if (failure is kotlinx.coroutines.CancellationException) throw failure
            return failure(PlatformFailureName.describe(failure))
        } finally {
            result.cancel()
            if (bound.get()) runCatching { app.unbindService(connection) }
        }
    }

    private fun failure(detail: String) = SrcuTimingObservation(SrcuTimingCollection.IPC_FAILED, failureDetail = detail)
    companion object { private val admission = Mutex() }
}
