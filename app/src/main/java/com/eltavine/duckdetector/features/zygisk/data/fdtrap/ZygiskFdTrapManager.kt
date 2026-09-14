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
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
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

        fun finish(result: ZygiskFdTrapDetectionResult) {
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

            override fun onNullBinding(name: ComponentName?) {
                finish(
                    ZygiskFdTrapDetectionResult.fromResultCode(
                        resultCode = ZygiskFdTrapNativeBridge.RESULT_BIND_FAILED,
                        detail = "Detector service returned a null binder.",
                    ),
                )
            }

            override fun onServiceDisconnected(name: ComponentName?) = Unit
        }

        continuation.invokeOnCancellation {
            requestCleanup()
        }
        if (!continuation.isActive) {
            return@suspendCancellableCoroutine
        }

        val intent = Intent(context, ZygiskFdTrapDetectorService::class.java)
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
            finish(
                ZygiskFdTrapDetectionResult.fromResultCode(
                    resultCode = ZygiskFdTrapNativeBridge.RESULT_BIND_FAILED,
                    detail = "The dedicated FD trap detector process could not be bound.",
                ),
            )
            return@suspendCancellableCoroutine
        }
    }

    companion object {
        private const val DETECTION_TIMEOUT_MS = 7_000L
        private val REMOTE_CALLBACK_EXECUTOR = Dispatchers.IO.asExecutor()
    }
}
