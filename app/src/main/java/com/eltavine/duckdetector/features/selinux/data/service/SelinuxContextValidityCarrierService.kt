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
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValidityBridge
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValidityPayloadCodec
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValiditySnapshot

class SelinuxContextValidityCarrierService : Service() {

    private val nativeBridge = SelinuxContextValidityBridge()

    private val binder = object : Binder() {
        override fun onTransact(
            code: Int,
            data: Parcel,
            reply: Parcel?,
            flags: Int,
        ): Boolean {
            return when (code) {
                INTERFACE_TRANSACTION -> {
                    reply?.writeString(SelinuxContextValidityCarrierProtocol.DESCRIPTOR)
                    true
                }

                SelinuxContextValidityCarrierProtocol.TRANSACTION_COLLECT_SNAPSHOT -> {
                    data.enforceInterface(SelinuxContextValidityCarrierProtocol.DESCRIPTOR)
                    reply?.writeNoException()
                    reply?.writeString(buildSnapshotPayload())
                    true
                }

                else -> super.onTransact(code, data, reply, flags)
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    private fun buildSnapshotPayload(): String {
        return runCatching {
            SelinuxContextValidityPayloadCodec.encode(nativeBridge.collectSnapshot())
        }.getOrElse { throwable ->
            SelinuxContextValidityPayloadCodec.encode(
                SelinuxContextValiditySnapshot(
                    failureReason = throwable.message ?: "SELinux carrier probe failed.",
                    notes = listOf("SELinux carrier probe crashed before collecting a snapshot."),
                ),
            )
        }
    }
}
