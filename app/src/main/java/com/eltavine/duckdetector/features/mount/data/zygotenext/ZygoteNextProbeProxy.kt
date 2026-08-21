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

import android.os.IBinder
import android.os.Parcel

class ZygoteNextProbeProxy(
    private val remote: IBinder,
) {

    fun collect(): String {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            // AIBinder_Class enforces its descriptor before invoking the native onTransact.
            data.writeInterfaceToken(ZygoteNextProbeProtocol.DESCRIPTOR)
            val handled = remote.transact(
                ZygoteNextProbeProtocol.TRANSACTION_COLLECT,
                data,
                reply,
                0,
            )
            check(handled) { "Native zygote_next Binder rejected the snapshot transaction." }
            reply.readException()
            reply.readString().orEmpty()
        } finally {
            data.recycle()
            reply.recycle()
        }
    }
}
