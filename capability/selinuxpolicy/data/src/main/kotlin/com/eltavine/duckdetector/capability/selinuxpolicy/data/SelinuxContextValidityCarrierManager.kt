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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.Process
import android.os.SystemClock
import android.util.Log
import com.eltavine.duckdetector.core.platform.AppZygoteStartGate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

public open class SelinuxContextValidityCarrierManager(
    private val context: Context? = null,
    private val serviceClass: Class<out Service> = SelinuxContextValidityCarrierService::class.java,
) {

    /**
     * Collects the carrier snapshot for a scan that started at [scanStartedAt], on the
     * [SystemClock.elapsedRealtime] clock. Another detector's collection from the same scan is
     * reused rather than starting the carrier's app zygote a second time.
     */
    public open suspend fun collectSnapshot(scanStartedAt: Long): SelinuxContextValiditySnapshot {
        val appContext = context?.applicationContext ?: return carrierFailureSnapshot(
            "SELinux carrier service unavailable.",
        )
        trace("request scan=$scanStartedAt package=${appContext.packageName} service=${serviceClass.name}")
        val snapshot = sharedCollection(serviceClass).collect(scanStartedAt) {
            trace("shared collection miss scan=$scanStartedAt")
            withTimeoutOrNull(DETECTION_TIMEOUT_MS) {
                AppZygoteStartGate.Default.admit(
                    scanStartedAt = scanStartedAt,
                    refused = {
                        trace("start gate refused scan=$scanStartedAt")
                        failedAttempt(SKIPPED_AFTER_FAILED_START)
                    },
                    stoppedBeforeConnecting = CarrierAttempt::stoppedBeforeConnecting,
                    attempt = { performRemoteSnapshotCollection(appContext) },
                ).snapshot
            } ?: carrierFailureSnapshot(
                "SELinux carrier probe timed out.",
            )
        }
        trace("return scan=$scanStartedAt available=${snapshot.available} carrier=${snapshot.carrierContext} " +
            "avc=${snapshot.avcLookup.state} pairs=${snapshot.avcLookup.pairs} failure=${snapshot.failureReason}")
        return snapshot
    }

    private suspend fun performRemoteSnapshotCollection(context: Context): CarrierAttempt {
        return performRemoteCall(
            context = context,
            onConnected = { proxy ->
                trace("snapshot transaction begin")
                val raw = proxy.collectSnapshot()
                trace("snapshot transaction returned chars=${raw.length}")
                CarrierAttempt(
                    snapshot = SelinuxContextValidityBridge().parse(raw),
                    stoppedBeforeConnecting = false,
                )
            },
            onNullBinder = { failedAttempt("SELinux carrier service returned a null binder.") },
            onBindingDied = { connected ->
                failedAttempt(
                    reason = "The dedicated SELinux carrier binding died before it answered.",
                    stoppedBeforeConnecting = !connected,
                )
            },
            onError = { error -> failedAttempt(error) },
        )
    }

    private fun failedAttempt(
        reason: String,
        stoppedBeforeConnecting: Boolean = false,
    ): CarrierAttempt = CarrierAttempt(
        snapshot = carrierFailureSnapshot(reason),
        stoppedBeforeConnecting = stoppedBeforeConnecting,
    )

    private class CarrierAttempt(
        val snapshot: SelinuxContextValiditySnapshot,
        val stoppedBeforeConnecting: Boolean,
    )

    private fun carrierFailureSnapshot(
        reason: String,
    ): SelinuxContextValiditySnapshot {
        return SelinuxContextValiditySnapshot(
            dirtyPolicyFailureReason = reason,
            javaDirtyPolicyFailureReason = reason,
            policyloadSeqnoState = SelinuxPolicyloadSeqnoState.UNAVAILABLE.name,
            policyloadSeqnoFailureReason = reason,
            procAttrCurrentFailureReason = reason,
            avcLookup = SelinuxAvcLookupSnapshot(
                state = SelinuxAvcLookupState.UNAVAILABLE,
                failureReason = reason,
            ),
            failureReason = reason,
        )
    }

    private suspend fun <T> performRemoteCall(
        context: Context,
        onConnected: (SelinuxContextValidityCarrierProxy) -> T,
        onNullBinder: () -> T,
        onBindingDied: (connected: Boolean) -> T,
        onError: (String) -> T,
    ): T = suspendCancellableCoroutine { continuation ->
        val attemptStartedAt = SystemClock.elapsedRealtimeNanos()
        fun event(message: String) = trace("bind=$attemptStartedAt " +
            "elapsedMs=${(SystemClock.elapsedRealtimeNanos() - attemptStartedAt) / 1_000_000} $message")
        val bindAttemptFinished = AtomicBoolean(false)
        val cleanupRequested = AtomicBoolean(false)
        val unbindAttempted = AtomicBoolean(false)
        val completionAttempted = AtomicBoolean(false)
        val connected = AtomicBoolean(false)
        lateinit var connection: ServiceConnection

        fun requestCleanup() {
            cleanupRequested.set(true)
            if (bindAttemptFinished.get() && unbindAttempted.compareAndSet(false, true)) {
                event("unbind begin connected=${connected.get()} active=${continuation.isActive}")
                runCatching { context.unbindService(connection) }
                    .onSuccess { event("unbind returned") }
                    .onFailure { event("unbind failed ${it.javaClass.simpleName}: ${it.message}") }
            }
        }

        fun finish(result: T) {
            requestCleanup()
            if (completionAttempted.compareAndSet(false, true)) {
                event("completion resume connected=${connected.get()} active=${continuation.isActive}")
                continuation.resume(result)
            }
        }

        connection = object : ServiceConnection {
            override fun onServiceConnected(
                name: ComponentName?,
                service: IBinder?,
            ) {
                event("onServiceConnected component=$name binder=${service?.let { System.identityHashCode(it) }} " +
                    "alive=${service?.isBinderAlive}")
                connected.set(true)
                if (service == null) {
                    finish(onNullBinder())
                    return
                }
                try {
                    val proxy = SelinuxContextValidityCarrierProxy(service)
                    finish(onConnected(proxy))
                } catch (throwable: Throwable) {
                    event("connected transaction failed ${throwable.javaClass.simpleName}: ${throwable.message}")
                    finish(onError(throwable.message ?: "Binder call failed."))
                }
            }

            override fun onNullBinding(name: ComponentName?) {
                event("onNullBinding component=$name")
                finish(onNullBinder())
            }

            // A carrier brought down before it connected, as when its app zygote cannot start, is
            // reported only here (frameworks/base LoadedApk.ServiceDispatcher.doConnected, dead).
            override fun onBindingDied(name: ComponentName?) {
                event("onBindingDied component=$name connected=${connected.get()}")
                finish(onBindingDied(connected.get()))
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                event("onServiceDisconnected component=$name connected=${connected.get()}")
            }
        }

        continuation.invokeOnCancellation {
            event("cancelled connected=${connected.get()} cause=${it?.javaClass?.simpleName}: ${it?.message}")
            requestCleanup()
        }
        if (!continuation.isActive) {
            return@suspendCancellableCoroutine
        }

        val intent = Intent(context, serviceClass)
        runCatching { context.packageManager.getServiceInfo(requireNotNull(intent.component), 0) }
            .onSuccess {
                event("service metadata process=${it.processName} flags=${it.flags} " +
                    "appProcess=${it.applicationInfo.processName} appUid=${it.applicationInfo.uid} " +
                    "apk=${it.applicationInfo.sourceDir}")
            }.onFailure { event("service metadata failed ${it.message}") }
        // onServiceConnected below makes a blocking Binder call, so it must not run on the
        // main thread's executor - that previously froze the UI (and could trigger an ANR)
        // for as long as the remote process took to answer.
        val bound = runCatching {
            event("bindService begin component=${intent.component}")
            context.bindService(intent, Context.BIND_AUTO_CREATE, REMOTE_CALLBACK_EXECUTOR, connection)
        }.onFailure { event("bindService failed ${it.javaClass.simpleName}: ${it.message}") }.getOrDefault(false)
        event("bindService returned bound=$bound")

        // ActivityManager may publish an already-running service before bindService() returns.
        // The executor callback can therefore request cleanup before the bind attempt finishes.
        bindAttemptFinished.set(true)
        if (cleanupRequested.get()) {
            requestCleanup()
        }

        if (!bound) {
            finish(onError("The dedicated SELinux carrier process could not be bound."))
            return@suspendCancellableCoroutine
        }
    }

    public companion object {
        private const val TRACE_TAG = "DuckSelinuxCarrier"
        private const val DETECTION_TIMEOUT_MS = 15_000L
        private const val SKIPPED_AFTER_FAILED_START =
            "Not started: an app zygote carrier was stopped before it connected earlier in this " +
                "scan, and starting another would stop the app's other helper processes again."
        private val REMOTE_CALLBACK_EXECUTOR = Dispatchers.IO.asExecutor()
        private val sharedCollections =
            ConcurrentHashMap<Class<out Service>, ScanSharedCollection<SelinuxContextValiditySnapshot>>()

        private fun trace(message: String) {
            Log.i(TRACE_TAG, "pid=${Process.myPid()} tid=${Process.myTid()} uid=${Process.myUid()} $message")
        }

        private fun sharedCollection(
            serviceClass: Class<out Service>,
        ): ScanSharedCollection<SelinuxContextValiditySnapshot> =
            sharedCollections.computeIfAbsent(serviceClass) {
                ScanSharedCollection(clock = SystemClock::elapsedRealtime)
            }
    }
}
