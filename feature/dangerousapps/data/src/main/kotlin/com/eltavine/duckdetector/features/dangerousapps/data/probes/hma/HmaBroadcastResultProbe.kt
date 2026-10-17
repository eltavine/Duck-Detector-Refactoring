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

package com.eltavine.duckdetector.features.dangerousapps.data.probes.hma

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaBehaviorCheck
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCallbackObservation
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCallbackFailure
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import kotlin.coroutines.resume
import kotlin.coroutines.cancellation.CancellationException

internal class HmaBroadcastResultProbe(
    private val context: Context,
    private val platform: HmaPlatformCalls,
) {
    suspend fun run(packages: List<String>): List<HmaBehaviorCheck> =
        HmaBroadcastComparisonProbe().run(context.packageName, packages, ::receive)

    private suspend fun receive(packageName: String): HmaCallbackObservation =
        withTimeoutOrNull(CALLBACK_TIMEOUT_MS) {
            suspendCancellableCoroutine { continuation ->
                val token = UUID.randomUUID().toString()
                val sentIntent = platform.intent(packageName).putExtra(TOKEN_KEY, token)
                val expectedIntent = Intent(sentIntent)
                val receiver = object : BroadcastReceiver() {
                    override fun onReceive(context: Context?, intent: Intent?) {
                        val observation = try {
                            HmaCallbackObservation(
                                received = true,
                                ordered = isOrderedBroadcast,
                                sticky = isInitialStickyBroadcast,
                                payloadPreserved = resultCode == RESULT_CODE && resultData == token &&
                                    getResultExtras(false)?.getString(TOKEN_KEY) == token,
                                intentPreserved = intent?.filterEquals(expectedIntent) == true &&
                                    intent.getStringExtra(TOKEN_KEY) == token,
                            )
                        } catch (_: Exception) {
                            HmaCallbackObservation(true, failure = HmaCallbackFailure.FAILED)
                        }
                        if (continuation.isActive) continuation.resume(observation)
                    }
                }
                try {
                    context.sendOrderedBroadcast(sentIntent, null, receiver,
                        Handler(Looper.getMainLooper()), RESULT_CODE, token,
                        Bundle().apply { putString(TOKEN_KEY, token) })
                } catch (failure: Exception) {
                    if (failure is CancellationException) throw failure
                    val outcome = if (failure is SecurityException) HmaCallbackFailure.PERMISSION_DENIED else HmaCallbackFailure.FAILED
                    if (continuation.isActive) continuation.resume(HmaCallbackObservation(false, failure = outcome))
                }
            }
        } ?: HmaCallbackObservation(false, failure = HmaCallbackFailure.TIMED_OUT)

    private companion object {
        const val CALLBACK_TIMEOUT_MS = 1000L
        const val RESULT_CODE = 0x484D41
        const val TOKEN_KEY = "probe_token"
    }
}
