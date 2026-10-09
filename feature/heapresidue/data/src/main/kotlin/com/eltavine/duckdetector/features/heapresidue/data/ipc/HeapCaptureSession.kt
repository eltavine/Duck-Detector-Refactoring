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

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import com.eltavine.duckdetector.core.evidence.NamedFailure
import java.io.IOException
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
import kotlinx.coroutines.suspendCancellableCoroutine

/** A binding failure is a probe result, never a coroutine cancellation. */
internal class HeapServiceUnavailableException(message: String) : IOException(message), NamedFailure {
    override val failureName: String = "HeapServiceUnavailableException"
}

/** Each session names a new isolated instance, with no app-zygote or external entry point. */
internal class HeapCaptureSession(private val context: Context) {
    val result = CompletableDeferred<HeapDumpResult>()
    // Context.bindService: unbind regardless of the bind result. The IO caller closes in finally.
    private val connections = mutableListOf<ServiceConnection>()
    private val callback = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code != HeapDumpProtocol.RESULT) return super.onTransact(code, data, reply, flags)
            data.enforceInterface(HeapDumpProtocol.CALLBACK)
            val value = HeapDumpResult(HeapDumpStatus.fromWire(data.readInt()), data.readLong(), data.readLong(), data.readLong())
            data.requireFullyConsumed()
            result.complete(value)
            return true
        }
    }

    // ActivityManager force-stops every service of this package when any of its processes fails to
    // start (ProcessList.handleProcessStart -> forceStopPackageLocked, "start failure"), killing a
    // binding that has not connected. Nothing was sent to that child, so a fresh instance is bound.
    suspend fun connect(): IBinder {
        repeat(BIND_ATTEMPTS) { bindOnce()?.let { return it } }
        throw HeapServiceUnavailableException("Isolated heap service binding died before connecting")
    }

    // Null when the binding died before the service connected.
    private suspend fun bindOnce(): IBinder? = suspendCancellableCoroutine { continuation ->
        val connected = AtomicBoolean(false)
        val settled = AtomicBoolean(false)
        fun settle(outcome: Result<IBinder?>) {
            if (settled.compareAndSet(false, true)) continuation.resumeWith(outcome)
        }
        fun unavailable(reason: String) = settle(Result.failure(HeapServiceUnavailableException(reason)))
        // A connected child that dies can no longer report; the reader then sees EOF or truncation.
        fun lost() { result.complete(HeapDumpResult(HeapDumpStatus.DUMP_FAILED)) }
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                if (service == null) return unavailable("Isolated heap service returned no binder")
                connected.set(true)
                settle(Result.success(service))
            }
            override fun onServiceDisconnected(name: ComponentName?) = lost()
            override fun onBindingDied(name: ComponentName?) = if (connected.get()) lost() else settle(Result.success(null))
            override fun onNullBinding(name: ComponentName?) = unavailable("Isolated heap service returned a null binding")
        }
        connections += connection
        val bound = context.bindIsolatedService(
            Intent(context, IsolatedHeapDumpService::class.java), Context.BIND_AUTO_CREATE,
            "heap_" + UUID.randomUUID().toString().replace("-", ""), CALLBACK_EXECUTOR, connection,
        )
        if (!bound) unavailable("Isolated heap service could not be bound")
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
        connections.forEach { runCatching { context.unbindService(it) } }
        connections.clear()
        result.cancel()
    }

    private companion object {
        const val BIND_ATTEMPTS = 2
        // Callbacks only settle state; off the main thread they also run while a host blocks it.
        val CALLBACK_EXECUTOR = Dispatchers.IO.asExecutor()
    }
}
