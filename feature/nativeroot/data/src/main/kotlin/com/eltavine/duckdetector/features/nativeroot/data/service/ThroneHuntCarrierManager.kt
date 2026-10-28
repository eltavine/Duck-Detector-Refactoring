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

package com.eltavine.duckdetector.features.nativeroot.data.service

import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import com.eltavine.duckdetector.core.native.NativeCollectionOutcome
import com.eltavine.duckdetector.core.native.NativeCollectionStatus
import com.eltavine.duckdetector.core.platform.AppZygoteCarrierLease
import com.eltavine.duckdetector.core.platform.AppZygoteStartGate
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

open class ThroneHuntCarrierManager(
    private val context: Context? = null,
    private val serviceClass: Class<out Service> = ThroneHuntCarrierService::class.java,
) {

    // The connection is held for the whole oracle round. Rebinding between setup and drain would
    // destroy/recreate an isolated process around a 13 s observation window and re-arm startup
    // noise exactly where the verdict has to be measured.
    // 连接在整轮 oracle 内保持存活；在 setup 和 drain 之间反复 bind/unbind 会在 13 秒
    // 观察窗口边缘销毁并重建 isolated 进程，把启动噪声重新引入本应只测量 verdict 的窗口。
    private var activeContext: Context? = null
    private var activeConnection: ServiceConnection? = null
    private var activeProxy: ThroneHuntCarrierProxy? = null
    private var activeLease: AppZygoteCarrierLease? = null

    // Setup call. Safe to repeat: it never reads the event stream. [scanStartedAt] is the scan's
    // start on the SystemClock.elapsedRealtime clock, which the app zygote start gate compares.
    open suspend fun collectSnapshot(scanStartedAt: Long): ThroneHuntCarrierState {
        return performRemoteCollection(
            scanStartedAt = scanStartedAt,
            onConnected = { proxy ->
                ThroneHuntCarrierPayloadCodec.decode(proxy.collectSnapshot())
            },
        )
    }

    // Verdict call. Reading the event stream consumes it, so call this exactly once per round,
    // after the stimulus window has elapsed.
    open suspend fun drainEvents(scanStartedAt: Long): ThroneHuntCarrierState {
        return performRemoteCollection(
            scanStartedAt = scanStartedAt,
            onConnected = { proxy ->
                ThroneHuntCarrierPayloadCodec.decode(proxy.drainEvents())
            },
        )
    }

    private suspend fun performRemoteCollection(
        scanStartedAt: Long,
        onConnected: (ThroneHuntCarrierProxy) -> ThroneHuntCarrierState,
    ): ThroneHuntCarrierState {
        val appContext = context?.applicationContext ?: return carrierFailureState(
            "Throne hunt carrier service unavailable.",
        )
        return withTimeoutOrNull(DETECTION_TIMEOUT_MS) {
            val proxy = synchronized(this@ThroneHuntCarrierManager) { activeProxy }
                ?: when (val connection = connectThroughGate(appContext, scanStartedAt)) {
                    is CarrierConnection.Connected -> connection.proxy
                    is CarrierConnection.Failed -> return@withTimeoutOrNull carrierFailureState(
                        connection.reason,
                    )
                }

            try {
                onConnected(proxy)
            } catch (throwable: Throwable) {
                close()
                carrierFailureState(throwable.message ?: "Binder call failed.")
            }
        } ?: carrierFailureState("Throne hunt carrier connection or transaction timed out.")
    }

    private fun carrierFailureState(reason: String): ThroneHuntCarrierState {
        // A bind/timeout/IPC failure is support evidence, not a collected carrier result. Marking
        // it BRIDGE_FAILED prevents the round from reading the empty carrier as a clean zero.
        // bind/超时/IPC 失败是支持性证据，不是已采集的 carrier 结果；标记为
        // BRIDGE_FAILED，避免 round 把空 carrier 读成 clean zero。
        return ThroneHuntCarrierState(
            collection = NativeCollectionStatus.failed(
                NativeCollectionOutcome.BRIDGE_FAILED,
                IllegalStateException(reason),
            ),
            failureReason = reason,
        )
    }

    private suspend fun connectThroughGate(
        context: Context,
        scanStartedAt: Long,
    ): CarrierConnection = AppZygoteStartGate.Default.admit(
        scanStartedAt = scanStartedAt,
        refused = { CarrierConnection.Failed(SKIPPED_AFTER_FAILED_START) },
        stoppedBeforeConnecting = { connection ->
            connection is CarrierConnection.Failed && connection.stoppedBeforeConnecting
        },
        attempt = { connect(context) },
    )

    private suspend fun connect(context: Context): CarrierConnection =
        suspendCancellableCoroutine { continuation ->
            val bindAttemptFinished = AtomicBoolean(false)
            val cleanupRequested = AtomicBoolean(false)
            val unbindAttempted = AtomicBoolean(false)
            val completionAttempted = AtomicBoolean(false)
            val connected = AtomicBoolean(false)
            val carrierLease = AppZygoteCarrierLease()
            lateinit var connection: ServiceConnection

            fun requestCleanup() {
                cleanupRequested.set(true)
                if (bindAttemptFinished.get() && unbindAttempted.compareAndSet(false, true)) {
                    runCatching { context.unbindService(connection) }
                    // Unbind does not prove that the isolated child has exited. An attached lease
                    // stays active until Binder death; this only retires pre-connect failures.
                    carrierLease.bindingFailed()
                }
            }

            fun finish(outcome: CarrierConnection) {
                if (outcome is CarrierConnection.Failed) {
                    requestCleanup()
                }
                if (completionAttempted.compareAndSet(false, true)) {
                    continuation.resume(outcome)
                }
            }

            connection = object : ServiceConnection {
                override fun onServiceConnected(
                    name: ComponentName?,
                    service: IBinder?,
                ) {
                    if (!continuation.isActive) {
                        requestCleanup()
                        carrierLease.bindingFailed()
                        return
                    }
                    connected.set(true)
                    if (service == null) {
                        carrierLease.bindingFailed()
                        finish(CarrierConnection.Failed(NULL_BINDER))
                        return
                    }
                    if (!carrierLease.attach(service)) {
                        finish(
                            CarrierConnection.Failed(
                                "The throne hunt carrier died before its Binder could be observed.",
                            ),
                        )
                        return
                    }
                    try {
                        val proxy = ThroneHuntCarrierProxy(service)
                        synchronized(this@ThroneHuntCarrierManager) {
                            activeContext = context
                            activeConnection = connection
                            activeProxy = proxy
                            activeLease = carrierLease
                        }
                        if (!carrierLease.isActive) {
                            close()
                            finish(
                                CarrierConnection.Failed(
                                    "The throne hunt carrier Binder died during connection setup.",
                                ),
                            )
                            return
                        }
                        finish(CarrierConnection.Connected(proxy))
                    } catch (throwable: Throwable) {
                        finish(
                            CarrierConnection.Failed(
                                throwable.message ?: "The throne hunt carrier binder could not be used.",
                            ),
                        )
                    }
                }

                override fun onNullBinding(name: ComponentName?) {
                    carrierLease.bindingFailed()
                    finish(CarrierConnection.Failed(NULL_BINDER))
                }

                // A carrier brought down before it connected, as when its app zygote cannot start,
                // is reported only here (frameworks/base LoadedApk.ServiceDispatcher.doConnected,
                // dead). A binding that dies later must still be unbound before it can be rebound.
                override fun onBindingDied(name: ComponentName?) {
                    if (connected.get()) {
                        close()
                    } else {
                        finish(
                            CarrierConnection.Failed(
                                reason = "The throne hunt carrier binding died before it connected.",
                                stoppedBeforeConnecting = true,
                            ),
                        )
                    }
                }

                override fun onServiceDisconnected(name: ComponentName?) {
                    // Drop the dead proxy and unbind. The death recipient, not the unbind return,
                    // releases the lease after the child process actually exits.
                    close()
                }
            }

            continuation.invokeOnCancellation {
                requestCleanup()
            }
            if (!continuation.isActive) {
                carrierLease.bindingFailed()
                return@suspendCancellableCoroutine
            }

            val intent = Intent(context, serviceClass)
            // onServiceConnected may make a blocking Binder call, so it must not run on the main
            // thread's executor - that previously froze the UI and could trigger an ANR.
            val bound = runCatching {
                context.bindService(intent, Context.BIND_AUTO_CREATE, REMOTE_CALLBACK_EXECUTOR, connection)
            }.getOrDefault(false)

            bindAttemptFinished.set(true)
            if (cleanupRequested.get()) {
                requestCleanup()
            }

            if (!bound) {
                finish(CarrierConnection.Failed("The throne hunt carrier process could not be bound."))
            }
        }

    fun close() {
        val cleanup = synchronized(this) {
            val triple = Triple(activeContext, activeConnection, activeProxy)
            val lease = activeLease
            activeContext = null
            activeConnection = null
            activeProxy = null
            activeLease = null
            triple to lease
        }
        val (triple, lease) = cleanup
        val (context, connection, _) = triple
        if (context != null && connection != null) {
            runCatching { context.unbindService(connection) }
        }
        lease?.bindingFailed()
    }

    private sealed interface CarrierConnection {
        class Connected(val proxy: ThroneHuntCarrierProxy) : CarrierConnection

        class Failed(
            val reason: String,
            val stoppedBeforeConnecting: Boolean = false,
        ) : CarrierConnection
    }

    companion object {
        private const val DETECTION_TIMEOUT_MS = 15_000L
        private const val NULL_BINDER = "The throne hunt carrier returned a null binder."
        private const val SKIPPED_AFTER_FAILED_START =
            "Not started: an app zygote carrier was stopped before it connected earlier in this " +
                "scan, and starting another would stop the app's other helper processes again."
        private val REMOTE_CALLBACK_EXECUTOR = Dispatchers.IO.asExecutor()
    }
}
