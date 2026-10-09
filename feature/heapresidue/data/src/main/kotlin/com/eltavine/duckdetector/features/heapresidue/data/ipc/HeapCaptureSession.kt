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

package com.eltavine.duckdetector.features.heapresidue.data.ipc

import androidx.annotation.RequiresApi
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.suspendCancellableCoroutine

/** Each session names a new isolated instance, with no app-zygote or external entry point. */
@RequiresApi(36)
internal class HeapCaptureSession(private val context: Context) {
    val result = CompletableDeferred<HeapDumpResult>()
    private val bound = AtomicBoolean(false)
    private var connection: ServiceConnection? = null
    private val callback = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code != HeapDumpProtocol.RESULT) return super.onTransact(code, data, reply, flags)
            data.enforceInterface(HeapDumpProtocol.CALLBACK)
            val value = HeapDumpResult(HeapDumpStatus.fromWire(data.readInt()), data.readLong(), data.readLong(), data.readLong())
            data.enforceNoDataAvail()
            result.complete(value)
            return true
        }
    }

    suspend fun connect(): IBinder = suspendCancellableCoroutine { continuation ->
        val handled = AtomicBoolean(false)
        fun fail() {
            if (handled.compareAndSet(false, true)) continuation.cancel(IllegalStateException("Isolated heap service unavailable"))
            result.complete(HeapDumpResult(HeapDumpStatus.DUMP_FAILED))
        }
        val serviceConnection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                if (service == null) fail()
                else if (handled.compareAndSet(false, true)) continuation.resume(service)
            }
            override fun onServiceDisconnected(name: ComponentName?) = fail()
            override fun onBindingDied(name: ComponentName?) = fail()
            override fun onNullBinding(name: ComponentName?) = fail()
        }
        connection = serviceConnection
        // The IO caller owns cleanup in finally, including cancellation during bind registration.
        bound.set(context.bindIsolatedService(
            Intent(context, IsolatedHeapDumpService::class.java), Context.BIND_AUTO_CREATE,
            "heap_" + UUID.randomUUID().toString().replace("-", ""), context.mainExecutor, serviceConnection,
        ))
        if (!bound.get()) fail()
    }

    fun start(service: IBinder, writePipe: ParcelFileDescriptor) {
        val parcel = Parcel.obtain()
        try {
            parcel.writeInterfaceToken(HeapDumpProtocol.SERVICE)
            writePipe.writeToParcel(parcel, 0)
            parcel.writeStrongBinder(callback)
            check(service.transact(HeapDumpProtocol.DUMP, parcel, null, IBinder.FLAG_ONEWAY))
        } finally {
            parcel.recycle()
            // Only the isolated process keeps the writer; its close terminates the host's stream.
            writePipe.close()
        }
    }

    fun close() {
        if (bound.compareAndSet(true, false)) connection?.let { runCatching { context.unbindService(it) } }
        result.cancel()
    }
}
