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

package com.eltavine.duckdetector.features.virtualization.data.service

import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import com.eltavine.duckdetector.features.virtualization.data.native.SacrificialSyscallPackResult
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationNativeBridge
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteProfile
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteSnapshot
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

open class VirtualizationProbeManager(
    private val context: Context? = null,
    private val serviceClass: Class<out Service> = VirtualizationProbeService::class.java,
    private val expectedProfile: VirtualizationRemoteProfile = VirtualizationRemoteProfile.REGULAR,
    private val nativeBridge: VirtualizationNativeBridge = VirtualizationNativeBridge(),
) {

    open suspend fun collect(): VirtualizationRemoteSnapshot {
        val appContext = context?.applicationContext ?: return VirtualizationRemoteSnapshot()
        return withTimeoutOrNull(DETECTION_TIMEOUT_MS) {
            performRemoteCollection(appContext)
        } ?: VirtualizationRemoteSnapshot(
            available = false,
            errorDetail = "Virtualization helper process timed out.",
        )
    }

    open suspend fun runSacrificialSyscallPack(): SacrificialSyscallPackResult {
        val appContext = context?.applicationContext ?: return SacrificialSyscallPackResult()
        return withTimeoutOrNull(DETECTION_TIMEOUT_MS) {
            performRemoteCall(
                context = appContext,
                onConnected = { proxy ->
                    nativeBridge.parseSacrificialSyscallPack(proxy.runSacrificialSyscallPack())
                },
                onNullBinder = {
                    SacrificialSyscallPackResult(
                        available = true,
                        supported = false,
                        detail = "Detector service returned a null binder.",
                    )
                },
                onError = { error ->
                    SacrificialSyscallPackResult(
                        available = true,
                        supported = false,
                        detail = error,
                    )
                },
            )
        } ?: SacrificialSyscallPackResult(
            available = true,
            supported = false,
            detail = "Sacrificial syscall pack timed out.",
        )
    }

    private suspend fun performRemoteCollection(
        context: Context,
    ): VirtualizationRemoteSnapshot {
        val snapshot = performRemoteCall(
            context = context,
            onConnected = { proxy ->
                VirtualizationRemoteSnapshot.parse(proxy.collectSnapshot())
            },
            onNullBinder = {
                VirtualizationRemoteSnapshot(
                    available = false,
                    profile = expectedProfile,
                    errorDetail = "Detector service returned a null binder.",
                )
            },
            onError = { error ->
                VirtualizationRemoteSnapshot(
                    available = false,
                    profile = expectedProfile,
                    errorDetail = error,
                )
            },
        )
        return if (snapshot.available && snapshot.profile != expectedProfile) {
            snapshot.copy(
                available = false,
                errorDetail = "Helper profile mismatch. expected=$expectedProfile actual=${snapshot.profile}",
            )
        } else {
            snapshot
        }
    }

    private suspend fun <T> performRemoteCall(
        context: Context,
        onConnected: (VirtualizationProbeProxy) -> T,
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
                    val proxy = VirtualizationProbeProxy(service)
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
            finish(onError("The dedicated virtualization probe process could not be bound."))
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
