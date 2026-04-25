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

import android.os.IBinder
import android.os.Parcel

class VirtualizationProbeProxy(
    private val remote: IBinder,
) {

    fun collectSnapshot(): String {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            data.writeInterfaceToken(VirtualizationProbeProtocol.DESCRIPTOR)
            remote.transact(
                VirtualizationProbeProtocol.TRANSACTION_COLLECT_SNAPSHOT,
                data,
                reply,
                0,
            )
            reply.readException()
            reply.readString().orEmpty()
        } finally {
            data.recycle()
            reply.recycle()
        }
    }

    fun isNativeAvailable(): Boolean {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            data.writeInterfaceToken(VirtualizationProbeProtocol.DESCRIPTOR)
            remote.transact(
                VirtualizationProbeProtocol.TRANSACTION_IS_NATIVE_AVAILABLE,
                data,
                reply,
                0,
            )
            reply.readException()
            reply.readInt() != 0
        } finally {
            data.recycle()
            reply.recycle()
        }
    }

    fun runSacrificialSyscallPack(): String {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            data.writeInterfaceToken(VirtualizationProbeProtocol.DESCRIPTOR)
            remote.transact(
                VirtualizationProbeProtocol.TRANSACTION_RUN_SACRIFICIAL_SYSCALL_PACK,
                data,
                reply,
                0,
            )
            reply.readException()
            reply.readString().orEmpty()
        } finally {
            data.recycle()
            reply.recycle()
        }
    }
}
