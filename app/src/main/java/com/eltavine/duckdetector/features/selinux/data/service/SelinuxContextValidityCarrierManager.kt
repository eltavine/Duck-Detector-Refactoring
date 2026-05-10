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
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxContextValidityProbe
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxContextValidityProbeResult
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

open class SelinuxContextValidityCarrierManager(
    private val context: Context? = null,
    private val serviceClass: Class<out Service> = SelinuxContextValidityCarrierService::class.java,
    private val probe: SelinuxContextValidityProbe = SelinuxContextValidityProbe(),
) {

    open suspend fun collect(): SelinuxContextValidityProbeResult {
        val appContext = context?.applicationContext ?: return probe.interpret(
            SelinuxContextValiditySnapshot(
                failureReason = "SELinux carrier service unavailable.",
            ),
        )
        return withTimeoutOrNull(DETECTION_TIMEOUT_MS) {
            performRemoteCollection(appContext)
        } ?: probe.interpret(
            SelinuxContextValiditySnapshot(
                failureReason = "SELinux carrier probe timed out.",
            ),
        )
    }

    private suspend fun performRemoteCollection(context: Context): SelinuxContextValidityProbeResult {
        return performRemoteCall(
            context = context,
            onConnected = { proxy ->
                probe.interpret(
                    SelinuxContextValidityBridge().parse(proxy.collectSnapshot()),
                )
            },
            onNullBinder = {
                probe.interpret(
                    SelinuxContextValiditySnapshot(
                        failureReason = "SELinux carrier service returned a null binder.",
                    ),
                )
            },
            onError = { error ->
                probe.interpret(
                    SelinuxContextValiditySnapshot(
                        failureReason = error,
                    ),
                )
            },
        )
    }

    private suspend fun <T> performRemoteCall(
        context: Context,
        onConnected: (SelinuxContextValidityCarrierProxy) -> T,
        onNullBinder: () -> T,
        onError: (String) -> T,
    ): T = suspendCancellableCoroutine { continuation ->
        var bound = false
        lateinit var connection: ServiceConnection

        fun finish(result: T) {
            if (!continuation.isActive) {
                return
            }
            if (bound) {
                runCatching { context.unbindService(connection) }
                bound = false
            }
            continuation.resume(result)
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

            override fun onServiceDisconnected(name: ComponentName?) = Unit
        }

        val intent = Intent(context, serviceClass)
        bound = runCatching {
            context.bindService(intent, connection, Context.BIND_AUTO_CREATE)
        }.getOrDefault(false)
        if (!bound) {
            finish(onError("The dedicated SELinux carrier process could not be bound."))
            return@suspendCancellableCoroutine
        }

        continuation.invokeOnCancellation {
            if (bound) {
                runCatching { context.unbindService(connection) }
                bound = false
            }
        }
    }

    companion object {
        private const val DETECTION_TIMEOUT_MS = 6_000L
    }
}
