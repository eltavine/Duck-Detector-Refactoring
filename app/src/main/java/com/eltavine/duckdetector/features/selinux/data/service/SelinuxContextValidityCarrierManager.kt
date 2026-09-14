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

package com.eltavine.duckdetector.features.selinux.data.service

import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValidityBridge
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValiditySnapshot
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxPolicyloadSeqnoState
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

open class SelinuxContextValidityCarrierManager(
    private val context: Context? = null,
    private val serviceClass: Class<out Service> = SelinuxContextValidityCarrierService::class.java,
) {

    open suspend fun collectSnapshot(): SelinuxContextValiditySnapshot {
        val appContext = context?.applicationContext ?: return carrierFailureSnapshot(
            "SELinux carrier service unavailable.",
        )
        return withTimeoutOrNull(DETECTION_TIMEOUT_MS) {
            performRemoteSnapshotCollection(appContext)
        } ?: carrierFailureSnapshot(
            "SELinux carrier probe timed out.",
        )
    }

    private suspend fun performRemoteSnapshotCollection(context: Context): SelinuxContextValiditySnapshot {
        return performRemoteCall(
            context = context,
            onConnected = { proxy -> SelinuxContextValidityBridge().parse(proxy.collectSnapshot()) },
            onNullBinder = { carrierFailureSnapshot("SELinux carrier service returned a null binder.") },
            onError = { error -> carrierFailureSnapshot(error) },
        )
    }

    private fun carrierFailureSnapshot(
        reason: String,
    ): SelinuxContextValiditySnapshot {
        return SelinuxContextValiditySnapshot(
            dirtyPolicyFailureReason = reason,
            javaDirtyPolicyFailureReason = reason,
            policyloadSeqnoState = SelinuxPolicyloadSeqnoState.UNAVAILABLE.name,
            policyloadSeqnoFailureReason = reason,
            procAttrCurrentFailureReason = reason,
            failureReason = reason,
        )
    }

    private suspend fun <T> performRemoteCall(
        context: Context,
        onConnected: (SelinuxContextValidityCarrierProxy) -> T,
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
                    val proxy = SelinuxContextValidityCarrierProxy(service)
                    finish(onConnected(proxy))
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
        // onServiceConnected below makes a blocking Binder call, so it must not run on the
        // main thread's executor - that previously froze the UI (and could trigger an ANR)
        // for as long as the remote process took to answer.
        val bound = runCatching {
            context.bindService(intent, Context.BIND_AUTO_CREATE, REMOTE_CALLBACK_EXECUTOR, connection)
        }.getOrDefault(false)

        // ActivityManager may publish an already-running service before bindService() returns.
        // The executor callback can therefore request cleanup before the bind attempt finishes.
        bindAttemptFinished.set(true)
        if (cleanupRequested.get()) {
            requestCleanup()
        }

        if (!bound) {
            finish(onError("The dedicated SELinux carrier process could not be bound."))
            return@suspendCancellableCoroutine
        }
    }

    companion object {
        private const val DETECTION_TIMEOUT_MS = 15_000L
        private val REMOTE_CALLBACK_EXECUTOR = Dispatchers.IO.asExecutor()
    }
}
