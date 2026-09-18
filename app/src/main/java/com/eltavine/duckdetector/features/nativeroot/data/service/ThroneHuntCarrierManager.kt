/*
 * Copyright 2026 Duck Apps Contributor
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

import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

open class ThroneHuntCarrierManager(
    private val context: Context? = null,
    private val serviceClass: Class<out Service> = ThroneHuntCarrierService::class.java,
) {

    // Setup call. Safe to repeat: it never reads the event stream.
    open suspend fun collectSnapshot(): ThroneHuntCarrierState {
        return performRemoteCollection(
            onConnected = { proxy ->
                ThroneHuntCarrierPayloadCodec.decode(proxy.collectSnapshot())
            },
        )
    }

    // Verdict call. Reading the event stream consumes it, so call this exactly once per round,
    // after the stimulus window has elapsed.
    open suspend fun drainEvents(): ThroneHuntCarrierState {
        return performRemoteCollection(
            onConnected = { proxy ->
                ThroneHuntCarrierPayloadCodec.decode(proxy.drainEvents())
            },
        )
    }

    private suspend fun performRemoteCollection(
        onConnected: (ThroneHuntCarrierProxy) -> ThroneHuntCarrierState,
    ): ThroneHuntCarrierState {
        val appContext = context?.applicationContext ?: return carrierFailureState(
            "Throne hunt carrier service unavailable.",
        )
        return withTimeoutOrNull(DETECTION_TIMEOUT_MS) {
            performRemoteCall(
                context = appContext,
                onConnected = onConnected,
                onNullBinder = {
                    carrierFailureState("Throne hunt carrier service returned a null binder.")
                },
                onError = { error -> carrierFailureState(error) },
            )
        } ?: carrierFailureState("Throne hunt carrier probe timed out.")
    }

    private fun carrierFailureState(reason: String): ThroneHuntCarrierState {
        return ThroneHuntCarrierState(failureReason = reason)
    }

    private suspend fun <T> performRemoteCall(
        context: Context,
        onConnected: (ThroneHuntCarrierProxy) -> T,
        onNullBinder: () -> T,
        onError: (String) -> T,
    ): T = suspendCancellableCoroutine { continuation ->
        val bindAttemptFinished = AtomicBoolean(false)
        val cleanupRequested = AtomicBoolean(false)
        val unbindAttempted = AtomicBoolean(false)
        val completionAttempted = AtomicBoolean(false)
        lateinit var connection: ServiceConnection

        fun requestCleanup() {
            cleanupRequested.set(true)
            if (bindAttemptFinished.get() && unbindAttempted.compareAndSet(false, true)) {
                runCatching { context.unbindService(connection) }
            }
        }

        fun finish(result: T) {
            requestCleanup()
            if (completionAttempted.compareAndSet(false, true)) {
                continuation.resume(result)
            }
        }

        connection = object : ServiceConnection {
            override fun onServiceConnected(
                name: ComponentName?,
                service: IBinder?,
            ) {
                if (service == null) {
                    finish(onNullBinder())
                    return
                }
                try {
                    finish(onConnected(ThroneHuntCarrierProxy(service)))
                } catch (throwable: Throwable) {
                    finish(onError(throwable.message ?: "Binder call failed."))
                }
            }

            override fun onNullBinding(name: ComponentName?) {
                finish(onNullBinder())
            }

            override fun onServiceDisconnected(name: ComponentName?) = Unit
        }

        continuation.invokeOnCancellation {
            requestCleanup()
        }
        if (!continuation.isActive) {
            return@suspendCancellableCoroutine
        }

        val intent = Intent(context, serviceClass)
        // onServiceConnected makes a blocking Binder call, so it must not run on the main
        // thread's executor - that previously froze the UI and could trigger an ANR.
        val bound = runCatching {
            context.bindService(intent, Context.BIND_AUTO_CREATE, REMOTE_CALLBACK_EXECUTOR, connection)
        }.getOrDefault(false)

        bindAttemptFinished.set(true)
        if (cleanupRequested.get()) {
            requestCleanup()
        }

        if (!bound) {
            finish(onError("The dedicated throne hunt carrier process could not be bound."))
            return@suspendCancellableCoroutine
        }
    }

    companion object {
        private const val DETECTION_TIMEOUT_MS = 15_000L
        private val REMOTE_CALLBACK_EXECUTOR = Dispatchers.IO.asExecutor()
    }
}
