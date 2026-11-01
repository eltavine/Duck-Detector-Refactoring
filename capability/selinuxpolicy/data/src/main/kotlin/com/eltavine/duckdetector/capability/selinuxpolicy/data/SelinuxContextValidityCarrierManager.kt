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
import com.eltavine.duckdetector.core.platform.AppZygoteCarrierLease
import com.eltavine.duckdetector.core.platform.AppZygoteStartGate
import com.eltavine.duckdetector.core.evidence.ScanEpoch
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

public open class SelinuxContextValidityCarrierManager(
    private val context: Context? = null,
    private val serviceClass: Class<out Service> = SelinuxContextValidityCarrierService::class.java,
) {
    private val generationStore: SelinuxAppZygoteGenerationStore? by lazy {
        context?.applicationContext?.let(::SharedPreferencesSelinuxAppZygoteGenerationStore)
    }
    /**
     * One dashboard/SDK scan shares a single epoch across SELinux and LSPosed detectors.
     */
    public open suspend fun collectSnapshot(scan: ScanEpoch): SelinuxContextValiditySnapshot {
        val appContext = context?.applicationContext ?: return carrierFailureSnapshot(
            "SELinux carrier service unavailable.",
        )
        val store = generationStore ?: return carrierFailureSnapshot(
            SelinuxAppZygoteRecovery.GENERATION_FENCE_UNAVAILABLE,
        )
        trace("request scan=${scan.id} package=${appContext.packageName} service=${serviceClass.name}")
        val snapshot = sharedCollection(serviceClass).collect(scan) {
            trace("shared collection miss scan=${scan.id}")
            boundedSingleAttempt(TOTAL_TIMEOUT_MS, onTimeout = {
                carrierFailureSnapshot("SELinux carrier probe timed out.")
            }) {
                val gate = AppZygoteStartGate.Default
                // Keep the admission lock from the first bind through recovery. Otherwise another
                // useAppZygote bind could cancel ActivityManager's delayed retirement between the
                // stale result and the point where recovery starts waiting for child death.
                gate.withExclusive {
                    val first = gate.admitExclusive(
                        scanStartedAt = scan.startedMillis,
                        refused = {
                            trace("start gate refused scan=${scan.id}")
                            failedAttempt(SKIPPED_AFTER_FAILED_START)
                        },
                        stoppedBeforeConnecting = CarrierAttempt::stoppedBeforeConnecting,
                        attempt = {
                            boundedSingleAttempt(DETECTION_TIMEOUT_MS, onTimeout = {
                                failedAttempt("SELinux carrier probe timed out.")
                            }) { performRemoteSnapshotCollection(appContext, scan, store) }
                        },
                    )
                    val recovered = SelinuxAppZygoteRecovery.recover(
                        first = first,
                        reason = { it.snapshot.failureReason },
                        parentPid = CarrierAttempt::parentPid,
                        awaitRetirement = { pid ->
                            trace("waiting for tracked App Zygote children to die oldParentPid=$pid scan=${scan.id}")
                            val drained = gate.awaitNoActiveLeases(CARRIER_RETIREMENT_TIMEOUT_MS)
                            if (!drained) {
                                trace("carrier retirement timed out oldParentPid=$pid scan=${scan.id}")
                                false
                            } else {
                                // AOSP schedules App-Zygote death 5 seconds after the last child
                                // leaves. Keep all new binds blocked for that interval plus a guard;
                                // the replacement parent and preload timestamp are still verified.
                                val quietWindowMs = APP_ZYGOTE_KILL_DELAY_MS + RETIREMENT_GUARD_MS
                                trace("all tracked carrier children died oldParentPid=$pid; " +
                                    "waiting quietWindowMs=$quietWindowMs scan=${scan.id}")
                                delay(quietWindowMs)
                                trace("retirement quiet window elapsed oldParentPid=$pid scan=${scan.id}")
                                true
                            }
                        },
                        retry = {
                            trace("retirement window complete; rebinding for a new preload scan=${scan.id}")
                            gate.admitExclusive(
                                scanStartedAt = scan.startedMillis,
                                refused = { failedAttempt(SKIPPED_AFTER_FAILED_START) },
                                stoppedBeforeConnecting = CarrierAttempt::stoppedBeforeConnecting,
                                attempt = {
                                    boundedSingleAttempt(REBIND_TIMEOUT_MS, onTimeout = {
                                        failedAttempt("SELinux carrier recovery binding timed out.")
                                    }) { performRemoteSnapshotCollection(appContext, scan, store) }
                                },
                            )
                        },
                        failure = { reason -> failedAttempt(reason) },
                    )
                    val acceptedKey = recovered.generationKey
                    if (acceptedKey != null && !store.commitAccepted(acceptedKey)) {
                        trace("generation fence commit failed scan=${scan.id} " +
                            "preloadPid=${acceptedKey.preloadPid}")
                        carrierFailureSnapshot("App Zygote generation fence could not be persisted.")
                            .copy(appZygoteParentPid = recovered.parentPid)
                    } else {
                        recovered.snapshot
                    }
                }
            }
        }
        trace("return scan=${scan.id} available=${snapshot.available} carrier=${snapshot.carrierContext} " +
            "avc=${snapshot.avcLookup.state} pairs=${snapshot.avcLookup.pairs} failure=${snapshot.failureReason}")
        return snapshot
    }

    private suspend fun performRemoteSnapshotCollection(
        context: Context,
        scan: ScanEpoch,
        store: SelinuxAppZygoteGenerationStore,
    ): CarrierAttempt {
        val codeAtBind = SelinuxCarrierCodeIdentity.readExpectedCode(context, serviceClass)
        return performRemoteCall(
            context = context,
            onConnected = { proxy ->
                trace("snapshot transaction begin")
                val raw = proxy.collectSnapshot()
                trace("snapshot transaction returned chars=${raw.length}")
                val codeAfter = SelinuxCarrierCodeIdentity.readExpectedCode(context, serviceClass)
                val origin = SelinuxCarrierProvenanceCodec.read(raw)
                val mismatch = provenanceFailureReason(
                    raw, codeAtBind, codeAfter, SystemClock.elapsedRealtimeNanos(),
                )
                val carrierParentPid = SelinuxCarrierProvenanceCodec.carrierParentPid(raw)
                val generationKey = origin?.toGenerationKey()
                val timestampStale = mismatch == null &&
                    SelinuxAppZygoteRecovery.stale(origin, scan.startedNanos)
                val fenceCheck = if (mismatch == null && !timestampStale && generationKey != null) {
                    store.check(generationKey)
                } else {
                    GenerationFenceCheck.NOT_ACCEPTED
                }
                val freshness = when {
                    mismatch != null -> mismatch
                    timestampStale -> SelinuxAppZygoteRecovery.STALE_PRELOAD
                    fenceCheck == GenerationFenceCheck.ALREADY_ACCEPTED ->
                        SelinuxAppZygoteRecovery.GENERATION_ALREADY_CONSUMED
                    fenceCheck == GenerationFenceCheck.UNAVAILABLE ->
                        SelinuxAppZygoteRecovery.GENERATION_FENCE_UNAVAILABLE
                    else -> null
                }
                trace("snapshot preloadPid=${origin?.preloadPid} carrierParentPid=" +
                    "$carrierParentPid versionCode=${origin?.versionCode} " +
                    "schema=${origin?.payloadSchemaVersion} buildRevision=${origin?.buildRevision} " +
                    "preloadStartedNanos=${origin?.startedNanos} scanStartedNanos=${scan.startedNanos} " +
                    "apk=${origin?.apkPath} expectedApk=${codeAfter?.apkPath} freshness=$freshness scan=${scan.id}")
                val snapshot = (if (freshness == null) SelinuxContextValidityBridge().parse(raw)
                else carrierFailureSnapshot(freshness)).copy(
                    appZygoteParentPid = carrierParentPid,
                    appZygotePreloadStartedNanos = origin?.startedNanos,
                    appZygotePreloadVersionCode = origin?.versionCode,
                    appZygotePreloadBuildRevision = origin?.buildRevision,
                )
                CarrierAttempt(
                    snapshot = snapshot,
                    stoppedBeforeConnecting = false,
                    parentPid = carrierParentPid,
                    generationKey = generationKey.takeIf { freshness == null && snapshot.available },
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

    internal fun provenanceFailureReason(
        raw: String,
        codeAtBind: SelinuxCarrierExpectedCode?,
        codeAtReply: SelinuxCarrierExpectedCode?,
        nowNanos: Long,
    ): String? = SelinuxCarrierCodeIdentity.provenanceFailureReason(
        raw, codeAtBind, codeAtReply, nowNanos,
    )

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
        val parentPid: Int? = null,
        val generationKey: SelinuxAppZygoteGenerationKey? = null,
    )

    private fun carrierFailureSnapshot(reason: String): SelinuxContextValiditySnapshot =
        SelinuxContextValiditySnapshot(
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
        var carrierLease: AppZygoteCarrierLease? = null
        lateinit var connection: ServiceConnection

        fun requestCleanup() {
            cleanupRequested.set(true)
            if (bindAttemptFinished.get() && unbindAttempted.compareAndSet(false, true)) {
                event("unbind begin connected=${connected.get()} active=${continuation.isActive}")
                runCatching { context.unbindService(connection) }
                    .onSuccess { event("unbind returned") }
                    .onFailure { event("unbind failed ${it.message}") }
                // Only a binding that never obtained a remote Binder can be retired here. For a
                // connected child the lease remains until its Binder process actually dies.
                carrierLease?.bindingFailed()
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
                if (!continuation.isActive) {
                    requestCleanup()
                    return
                }
                connected.set(true)
                if (service == null) {
                    carrierLease?.bindingFailed()
                    finish(onNullBinder())
                    return
                }
                try {
                    if (carrierLease?.attach(service) != true) {
                        event("remote Binder died before its App-Zygote lease could be attached")
                        finish(onError("The dedicated SELinux carrier died before its Binder could be observed."))
                        return
                    }
                    val proxy = SelinuxContextValidityCarrierProxy(service)
                    finish(onConnected(proxy))
                } catch (throwable: Throwable) {
                    event("connected transaction failed ${throwable.message}")
                    finish(onError(throwable.message ?: "Binder call failed."))
                }
            }

            override fun onNullBinding(name: ComponentName?) {
                event("onNullBinding component=$name")
                carrierLease?.bindingFailed()
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
            event("cancelled connected=${connected.get()} cause=${it?.message}")
            requestCleanup()
        }
        if (!continuation.isActive) {
            return@suspendCancellableCoroutine
        }
        carrierLease = AppZygoteCarrierLease()
        if (!continuation.isActive) {
            carrierLease.bindingFailed()
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
        }.onFailure { event("bindService failed ${it.message}") }.getOrDefault(false)
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
        private const val CARRIER_RETIREMENT_TIMEOUT_MS = 23_000L
        private const val APP_ZYGOTE_KILL_DELAY_MS = 5_000L
        private const val RETIREMENT_GUARD_MS = 1_000L
        private const val REBIND_TIMEOUT_MS = 8_000L
        private const val TOTAL_TIMEOUT_MS = DETECTION_TIMEOUT_MS + CARRIER_RETIREMENT_TIMEOUT_MS +
            APP_ZYGOTE_KILL_DELAY_MS + RETIREMENT_GUARD_MS + REBIND_TIMEOUT_MS
        private const val SKIPPED_AFTER_FAILED_START =
            "Not started: an app zygote carrier was stopped before it connected earlier in this " +
                "scan, and starting another would stop the app's other helper processes again."
        private val REMOTE_CALLBACK_EXECUTOR = Dispatchers.IO.asExecutor()
        private val sharedCollections =
            ConcurrentHashMap<Class<out Service>, ScanSharedCollection<SelinuxContextValiditySnapshot>>()
        internal suspend fun <T> boundedSingleAttempt(
            timeoutMs: Long,
            onTimeout: () -> T,
            attempt: suspend () -> T,
        ): T = withTimeoutOrNull(timeoutMs) { attempt() } ?: onTimeout()

        private fun trace(message: String) {
            Log.i(TRACE_TAG, "pid=${Process.myPid()} tid=${Process.myTid()} uid=${Process.myUid()} $message")
        }

        private fun sharedCollection(
            serviceClass: Class<out Service>,
        ): ScanSharedCollection<SelinuxContextValiditySnapshot> =
            sharedCollections.computeIfAbsent(serviceClass) { ScanSharedCollection() }
    }
}
