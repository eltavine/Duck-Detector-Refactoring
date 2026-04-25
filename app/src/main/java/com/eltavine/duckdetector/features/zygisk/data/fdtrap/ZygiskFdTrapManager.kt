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

package com.eltavine.duckdetector.features.zygisk.data.fdtrap

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

class ZygiskFdTrapManager(
    private val nativeBridge: ZygiskFdTrapNativeBridge = ZygiskFdTrapNativeBridge(),
) {

    suspend fun detect(
        context: Context,
    ): ZygiskFdTrapDetectionResult {
        if (!nativeBridge.isNativeAvailable()) {
            return ZygiskFdTrapDetectionResult.fromResultCode(
                resultCode = ZygiskFdTrapNativeBridge.RESULT_NATIVE_UNAVAILABLE,
                detail = "FD trap native bridge could not be loaded in the app process.",
            )
        }

        val trapFd = nativeBridge.setupTrapFd(context.cacheDir.absolutePath)
        if (trapFd < 0) {
            return ZygiskFdTrapDetectionResult.fromResultCode(
                resultCode = trapFd,
                detail = nativeBridge.getTrapDetails(),
            )
        }

        return try {
            withTimeoutOrNull(DETECTION_TIMEOUT_MS) {
                performRemoteDetection(context.applicationContext, trapFd)
            } ?: ZygiskFdTrapDetectionResult.fromResultCode(
                resultCode = ZygiskFdTrapNativeBridge.RESULT_TIMEOUT,
                detail = "Detector service timed out before the child-process verification returned.",
            )
        } finally {
            nativeBridge.cleanupTrapFd(trapFd)
        }
    }

    private suspend fun performRemoteDetection(
        context: Context,
        trapFd: Int,
    ): ZygiskFdTrapDetectionResult = suspendCancellableCoroutine { continuation ->
        var bound = false
        lateinit var connection: ServiceConnection

        fun finish(result: ZygiskFdTrapDetectionResult) {
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
                    finish(
                        ZygiskFdTrapDetectionResult.fromResultCode(
                            resultCode = ZygiskFdTrapNativeBridge.RESULT_BIND_FAILED,
                            detail = "Detector service returned a null binder.",
                        ),
                    )
                    return
                }

                try {
                    val proxy = ZygiskFdTrapDetectorProxy(service)
                    if (!proxy.isNativeAvailable()) {
                        finish(
                            ZygiskFdTrapDetectionResult.fromResultCode(
                                resultCode = ZygiskFdTrapNativeBridge.RESULT_NATIVE_UNAVAILABLE,
                                detail = "Detector service started but native FD trap helpers were unavailable there.",
                            ),
                        )
                        return
                    }

                    val pfd = ParcelFileDescriptor.fromFd(trapFd)
                    val resultCode = try {
                        proxy.performDetection(pfd)
                    } finally {
                        runCatching { pfd.close() }
                    }
                    val details = proxy.getDetectionDetails()
                    finish(
                        ZygiskFdTrapDetectionResult.fromResultCode(
                            resultCode = resultCode,
                            detail = details,
                        ),
                    )
                } catch (throwable: Throwable) {
                    finish(
                        ZygiskFdTrapDetectionResult.fromResultCode(
                            resultCode = ZygiskFdTrapNativeBridge.RESULT_BIND_FAILED,
                            detail = throwable.message ?: "FD trap Binder call failed.",
                            error = throwable.stackTraceToString(),
                        ),
                    )
                }
            }

            override fun onServiceDisconnected(name: ComponentName?) = Unit
        }

        val intent = Intent(context, ZygiskFdTrapDetectorService::class.java)
        bound = runCatching {
            context.bindService(intent, connection, Context.BIND_AUTO_CREATE)
        }.getOrDefault(false)
        if (!bound) {
            finish(
                ZygiskFdTrapDetectionResult.fromResultCode(
                    resultCode = ZygiskFdTrapNativeBridge.RESULT_BIND_FAILED,
                    detail = "The dedicated FD trap detector process could not be bound.",
                ),
            )
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
        private const val DETECTION_TIMEOUT_MS = 7_000L
    }
}
