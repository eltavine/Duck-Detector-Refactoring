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
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationNativeBridge
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteProfile

abstract class BaseVirtualizationProbeService : Service() {

    protected abstract val profile: VirtualizationRemoteProfile

    private val nativeBridge = VirtualizationNativeBridge()

    private val binder = object : Binder() {
        override fun onTransact(
            code: Int,
            data: Parcel,
            reply: Parcel?,
            flags: Int,
        ): Boolean {
            return when (code) {
                INTERFACE_TRANSACTION -> {
                    reply?.writeString(VirtualizationProbeProtocol.DESCRIPTOR)
                    true
                }

                VirtualizationProbeProtocol.TRANSACTION_COLLECT_SNAPSHOT -> {
                    data.enforceInterface(VirtualizationProbeProtocol.DESCRIPTOR)
                    reply?.writeNoException()
                    reply?.writeString(buildSnapshotPayload())
                    true
                }

                VirtualizationProbeProtocol.TRANSACTION_IS_NATIVE_AVAILABLE -> {
                    data.enforceInterface(VirtualizationProbeProtocol.DESCRIPTOR)
                    reply?.writeNoException()
                    reply?.writeInt(if (nativeBridge.isNativeAvailable()) 1 else 0)
                    true
                }

                VirtualizationProbeProtocol.TRANSACTION_RUN_SACRIFICIAL_SYSCALL_PACK -> {
                    data.enforceInterface(VirtualizationProbeProtocol.DESCRIPTOR)
                    reply?.writeNoException()
                    val payload = if (profile == VirtualizationRemoteProfile.REGULAR) {
                        nativeBridge.runSacrificialSyscallPack()
                    } else {
                        com.eltavine.duckdetector.features.virtualization.data.native.SacrificialSyscallPackResult(
                            available = true,
                            supported = false,
                            detail = "Sacrificial syscall pack is only allowed from the regular helper process.",
                        )
                    }
                    reply?.writeString(
                        buildString {
                            appendLine("AVAILABLE=${if (payload.available) 1 else 0}")
                            appendLine("SUPPORTED=${if (payload.supported) 1 else 0}")
                            appendLine("DISABLED=${if (payload.disabled) 1 else 0}")
                            appendLine(
                                "DETAIL=${
                                    payload.detail.replace("\n", "\\n").replace("\r", "\\r")
                                }",
                            )
                            payload.items.forEach { item ->
                                append("ITEM=")
                                append(item.label)
                                append('\t')
                                append(if (item.supported) 1 else 0)
                                append('\t')
                                append(item.completedAttempts)
                                append('\t')
                                append(item.suspiciousAttempts)
                                append('\t')
                                appendLine(
                                    item.detail.replace("\n", "\\n").replace("\r", "\\r"),
                                )
                                item.attempts.forEach { attempt ->
                                    append("ATTEMPT=")
                                    append(item.label)
                                    append('\t')
                                    append(if (attempt.suspicious) 1 else 0)
                                    append('\t')
                                    appendLine(
                                        attempt.detail.replace("\n", "\\n").replace("\r", "\\r"),
                                    )
                                }
                            }
                        },
                    )
                    true
                }

                else -> super.onTransact(code, data, reply, flags)
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    private fun buildSnapshotPayload(): String {
        return VirtualizationProbePayloadBuilder.buildSnapshotPayload(
            context = applicationContext,
            profile = profile,
            classLoader = javaClass.classLoader,
            nativeBridge = nativeBridge,
        )
    }
}

class VirtualizationProbeService : BaseVirtualizationProbeService() {
    override val profile: VirtualizationRemoteProfile = VirtualizationRemoteProfile.REGULAR
}

class VirtualizationIsolatedProbeService : BaseVirtualizationProbeService() {
    override val profile: VirtualizationRemoteProfile = VirtualizationRemoteProfile.ISOLATED
}
