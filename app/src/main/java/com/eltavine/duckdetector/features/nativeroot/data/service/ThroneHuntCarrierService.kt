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
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import com.eltavine.duckdetector.features.nativeroot.data.native.ThroneHuntWatchNativeBridge

class ThroneHuntCarrierService : Service() {

    private val binder = object : Binder() {
        override fun onTransact(
            code: Int,
            data: Parcel,
            reply: Parcel?,
            flags: Int,
        ): Boolean {
            return when (code) {
                INTERFACE_TRANSACTION -> {
                    reply?.writeString(ThroneHuntCarrierProtocol.DESCRIPTOR)
                    true
                }

                ThroneHuntCarrierProtocol.TRANSACTION_COLLECT_SNAPSHOT -> {
                    data.enforceInterface(ThroneHuntCarrierProtocol.DESCRIPTOR)
                    reply?.writeNoException()
                    reply?.writeString(buildSnapshotPayload())
                    true
                }

                ThroneHuntCarrierProtocol.TRANSACTION_DRAIN_EVENTS -> {
                    data.enforceInterface(ThroneHuntCarrierProtocol.DESCRIPTOR)
                    reply?.writeNoException()
                    reply?.writeString(buildEventPayload())
                    true
                }

                else -> super.onTransact(code, data, reply, flags)
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    private fun buildSnapshotPayload(): String {
        return runCatching { ThroneHuntCarrierPayloadCodec.encode(resolveCarrierState()) }
            .getOrElse { throwable ->
                ThroneHuntCarrierPayloadCodec.encode(
                    ThroneHuntCarrierState(
                        failureReason = throwable.message ?: "Throne hunt carrier probe failed.",
                        notes = listOf("Throne hunt carrier crashed before reading the watch state."),
                    )
                )
            }
    }

    // Only this path drains. Reading the event stream consumes it, so a setup call that drained
    // would swallow the traversal events raised later during the stimulus window.
    private fun buildEventPayload(): String {
        return runCatching {
            val state = resolveCarrierState()
            if (!state.watchInstalled) {
                return@runCatching ThroneHuntCarrierPayloadCodec.encode(
                    ThroneHuntCarrierState(
                        failureReason = state.failureReason
                            ?: "The app_zygote package directory watch was not installed.",
                        notes = state.notes,
                    )
                )
            }
            val events = ThroneHuntWatchNativeBridge().drainWatch(state.watchDescriptor)
            buildString {
                append(ThroneHuntCarrierPayloadCodec.encode(state))
                append("EVENT_DIRECTORY_OPEN=")
                append(events.directoryOpenCount)
                append('\n')
                append("EVENT_DIRECTORY_ACCESS=")
                append(events.directoryAccessCount)
                append('\n')
                append("EVENT_RAW=")
                append(events.rawEventCount)
                append('\n')
                append("EVENT_DETAIL=")
                append(events.detail)
                append('\n')
            }
        }.getOrElse { throwable ->
            ThroneHuntCarrierPayloadCodec.encode(
                ThroneHuntCarrierState(
                    failureReason = throwable.message ?: "Throne hunt event drain failed.",
                    notes = listOf("Throne hunt carrier crashed while draining the watch."),
                )
            )
        }
    }

    companion object {
        @Volatile
        private var cachedState: ThroneHuntCarrierState? = null

        // The app_zygote generation is fixed for the process lifetime, so the preloaded state is
        // decoded once and reused by every transaction.
        private fun resolveCarrierState(): ThroneHuntCarrierState {
            cachedState?.let { return it }
            val raw = ThroneHuntWatchInstaller.consumeForCarrier()
            if (!raw.isNullOrBlank()) {
                val decoded = ThroneHuntCarrierPayloadCodec.decode(raw)
                cachedState = decoded
                return decoded
            }
            return ThroneHuntCarrierState(
                failureReason = "Dedicated app_zygote preload state unavailable.",
                notes = listOf("Throne hunt carrier did not receive a preloaded app_zygote state."),
            )
        }

        internal fun clearCachedStateForTests() {
            cachedState = null
        }
    }
}
