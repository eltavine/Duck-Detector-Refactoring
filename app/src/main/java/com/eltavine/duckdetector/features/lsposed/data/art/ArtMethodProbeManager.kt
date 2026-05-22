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

package com.eltavine.duckdetector.features.lsposed.data.art

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

internal class ArtMethodProbeManager(
    private val context: Context,
    private val nativeBridge: ArtMethodNativeBridge = ArtMethodNativeBridge(),
) {

    suspend fun collectIsolatedSnapshot(): ArtMethodSnapshot {
        return withTimeoutOrNull(DETECTION_TIMEOUT_MS) {
            bindAndCollect(context.applicationContext)
        } ?: ArtMethodSnapshot()
    }

    private suspend fun bindAndCollect(
        appContext: Context,
    ): ArtMethodSnapshot = suspendCancellableCoroutine { continuation ->
        var bound = false
        lateinit var connection: ServiceConnection

        fun finish(snapshot: ArtMethodSnapshot) {
            if (!continuation.isActive) {
                return
            }
            if (bound) {
                runCatching { appContext.unbindService(connection) }
                bound = false
            }
            continuation.resume(snapshot)
        }

        connection = object : ServiceConnection {
            override fun onServiceConnected(
                name: ComponentName?,
                service: IBinder?,
            ) {
                if (service == null) {
                    finish(ArtMethodSnapshot())
                    return
                }

                val snapshot = runCatching {
                    nativeBridge.parse(ArtMethodProbeProxy(service).collectSnapshot())
                }.getOrDefault(ArtMethodSnapshot())
                finish(snapshot)
            }

            override fun onServiceDisconnected(name: ComponentName?) = Unit
        }

        bound = runCatching {
            appContext.bindService(
                Intent(appContext, ArtMethodProbeService::class.java),
                connection,
                Context.BIND_AUTO_CREATE,
            )
        }.getOrDefault(false)

        if (!bound) {
            finish(ArtMethodSnapshot())
            return@suspendCancellableCoroutine
        }

        continuation.invokeOnCancellation {
            if (bound) {
                runCatching { appContext.unbindService(connection) }
                bound = false
            }
        }
    }

    private companion object {
        private const val DETECTION_TIMEOUT_MS = 4_000L
    }
}
