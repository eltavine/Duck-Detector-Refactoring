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

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor

class ZygiskFdTrapDetectorService : Service() {

    private val nativeBridge = ZygiskFdTrapNativeBridge()
    private var lastDetectionDetails: String = "No FD trap detection performed."

    private val binder = object : Binder() {
        override fun onTransact(
            code: Int,
            data: Parcel,
            reply: Parcel?,
            flags: Int,
        ): Boolean {
            return when (code) {
                INTERFACE_TRANSACTION -> {
                    reply?.writeString(DESCRIPTOR)
                    true
                }

                TRANSACTION_PERFORM_DETECTION -> {
                    data.enforceInterface(DESCRIPTOR)
                    val pfd = if (data.readInt() != 0) {
                        ParcelFileDescriptor.CREATOR.createFromParcel(data)
                    } else {
                        null
                    }
                    val result = performDetection(pfd)
                    reply?.writeNoException()
                    reply?.writeInt(result)
                    true
                }

                TRANSACTION_GET_DETAILS -> {
                    data.enforceInterface(DESCRIPTOR)
                    reply?.writeNoException()
                    reply?.writeString(lastDetectionDetails)
                    true
                }

                TRANSACTION_IS_NATIVE_AVAILABLE -> {
                    data.enforceInterface(DESCRIPTOR)
                    reply?.writeNoException()
                    reply?.writeInt(if (nativeBridge.isNativeAvailable()) 1 else 0)
                    true
                }

                else -> super.onTransact(code, data, reply, flags)
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    private fun performDetection(
        pfd: ParcelFileDescriptor?,
    ): Int {
        if (pfd == null) {
            lastDetectionDetails = "Detector service received a null ParcelFileDescriptor."
            return ZygiskFdTrapNativeBridge.RESULT_BIND_FAILED
        }

        return try {
            val result = nativeBridge.verifyTrapFd(pfd.fd)
            lastDetectionDetails = nativeBridge.getTrapDetails()
            result
        } catch (throwable: Throwable) {
            lastDetectionDetails = throwable.message ?: "FD trap service verification failed."
            ZygiskFdTrapNativeBridge.RESULT_NATIVE_UNAVAILABLE
        } finally {
            runCatching { pfd.close() }
        }
    }

    companion object {
        const val DESCRIPTOR = "com.eltavine.duckdetector.features.zygisk.fdtrap"
        const val TRANSACTION_PERFORM_DETECTION = IBinder.FIRST_CALL_TRANSACTION + 0
        const val TRANSACTION_GET_DETAILS = IBinder.FIRST_CALL_TRANSACTION + 1
        const val TRANSACTION_IS_NATIVE_AVAILABLE = IBinder.FIRST_CALL_TRANSACTION + 2
    }
}
