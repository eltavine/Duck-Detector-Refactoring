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

package com.eltavine.duckdetector.features.mount.data.zygotenext

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Build
import android.os.IBinder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume

internal interface ZygoteNextServiceBinding {
    fun bind(connection: ServiceConnection): Boolean

    fun unbind(connection: ServiceConnection)
}

private class AndroidZygoteNextServiceBinding(
    private val context: Context,
) : ZygoteNextServiceBinding {

    override fun bind(connection: ServiceConnection): Boolean {
        return context.bindIsolatedService(
            Intent(context, ZygoteNextProbeService::class.java),
            Context.BIND_AUTO_CREATE,
            ZygoteNextProbeManager.ISOLATED_INSTANCE_NAME,
            context.mainExecutor,
            connection,
        )
    }

    override fun unbind(connection: ServiceConnection) {
        context.unbindService(connection)
    }
}

open class ZygoteNextProbeManager private constructor(
    private val sdkIntProvider: () -> Int,
    private val localProbe: ZygoteNextLocalProbe,
    private val serviceBinding: ZygoteNextServiceBinding?,
    private val timeoutMillis: Long,
    private val payloadCollector: (IBinder) -> String,
) {

    constructor(
        context: Context? = null,
        sdkIntProvider: () -> Int = { Build.VERSION.SDK_INT },
        localProbe: ZygoteNextLocalProbe = ZygoteNextLocalProbe(),
    ) : this(
        sdkIntProvider = sdkIntProvider,
        localProbe = localProbe,
        serviceBinding = context?.applicationContext?.let(::AndroidZygoteNextServiceBinding),
        timeoutMillis = DETECTION_TIMEOUT_MS,
        payloadCollector = { binder -> ZygoteNextProbeProxy(binder).collect() },
    )

    internal constructor(
        sdkIntProvider: () -> Int,
        localProbe: ZygoteNextLocalProbe,
        serviceBinding: ZygoteNextServiceBinding?,
        timeoutMillis: Long,
        payloadCollector: (IBinder) -> String,
        @Suppress("UNUSED_PARAMETER") testOnly: Unit,
    ) : this(
        sdkIntProvider = sdkIntProvider,
        localProbe = localProbe,
        serviceBinding = serviceBinding,
        timeoutMillis = timeoutMillis,
        payloadCollector = payloadCollector,
    )

    open suspend fun collect(): ZygoteNextProbeResult {
        val sdkInt = sdkIntProvider()
        if (sdkInt < ANDROID_17_API_LEVEL) {
            return ZygoteNextProbeResult.unsupported(sdkInt)
        }

        val mainProcess = localProbe.collect()
        val binding = serviceBinding ?: return ZygoteNextProbeResult.unavailable(
            sdkInt = sdkInt,
            detail = "Application context was unavailable for the zygote_next service.",
            mainProcess = mainProcess,
        )

        return withTimeoutOrNull(timeoutMillis) {
            bindAndCollect(binding, sdkInt, mainProcess)
        } ?: ZygoteNextProbeResult.unavailable(
            sdkInt = sdkInt,
            detail = "Zygote next native service timed out after ${timeoutMillis} ms.",
            mainProcess = mainProcess,
        )
    }

    private suspend fun bindAndCollect(
        binding: ZygoteNextServiceBinding,
        sdkInt: Int,
        mainProcess: ZygoteNextProcessSnapshot,
    ): ZygoteNextProbeResult = suspendCancellableCoroutine { continuation ->
        val bound = AtomicBoolean(true)
        val finished = AtomicBoolean(false)
        lateinit var connection: ServiceConnection

        fun finish(result: ZygoteNextProbeResult) {
            if (!finished.compareAndSet(false, true)) return
            if (bound.compareAndSet(true, false)) {
                runCatching { binding.unbind(connection) }
            }
            continuation.resume(result)
        }

        fun unavailable(detail: String): ZygoteNextProbeResult {
            return ZygoteNextProbeResult.unavailable(
                sdkInt = sdkInt,
                detail = detail,
                mainProcess = mainProcess,
            )
        }

        connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                if (service == null) {
                    finish(unavailable("Zygote next native service returned a null Binder."))
                    return
                }
                CoroutineScope(continuation.context).launch(Dispatchers.IO) {
                    val result = runCatching {
                        val isolatedProcess = ZygoteNextPayloadCodec.decode(
                            payloadCollector(service),
                        )
                        if (!isolatedProcess.available) {
                            unavailable(
                                isolatedProcess.errorDetail.ifBlank {
                                    "Zygote next native mount snapshot was unavailable."
                                },
                            )
                        } else {
                            ZygoteNextProbeResult(
                                state = ZygoteNextProbeState.READY,
                                sdkInt = sdkInt,
                                mainProcess = mainProcess,
                                isolatedProcess = isolatedProcess,
                                errorDetail = mainProcess.errorDetail,
                            )
                        }
                    }.getOrElse { throwable ->
                        unavailable(throwable.message ?: "Zygote next Binder payload failed.")
                    }
                    finish(result)
                }
            }

            override fun onNullBinding(name: ComponentName?) {
                finish(unavailable("Zygote next native service returned a null binding."))
            }

            override fun onBindingDied(name: ComponentName?) {
                finish(unavailable("Zygote next native service binding died."))
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                finish(unavailable("Zygote next native service disconnected."))
            }
        }

        val didBind = runCatching {
            binding.bind(connection)
        }.getOrDefault(false)
        if (!didBind) {
            bound.set(false)
            finish(unavailable("Zygote next native service could not be bound."))
            return@suspendCancellableCoroutine
        }

        continuation.invokeOnCancellation {
            if (finished.compareAndSet(false, true) && bound.compareAndSet(true, false)) {
                runCatching { binding.unbind(connection) }
            }
        }
    }

    companion object {
        const val ANDROID_17_API_LEVEL = 37
        internal const val ISOLATED_INSTANCE_NAME = "duck_zygote_next_mount"
        private const val DETECTION_TIMEOUT_MS = 10_000L
    }
}
