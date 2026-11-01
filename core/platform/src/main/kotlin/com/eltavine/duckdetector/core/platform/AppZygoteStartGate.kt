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

package com.eltavine.duckdetector.core.platform

import android.os.SystemClock
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Lets one app zygote carrier start at a time, and turns the rest of a scan away once one start
 * has failed.
 *
 * A package has one app zygote, which every `android:useAppZygote` service shares. When it cannot
 * start, ActivityManager stops all of the package's services, not only the one it was starting
 * (frameworks/base ProcessList.handleProcessStart -> forceStopPackageLocked, "start failure"), so
 * each further attempt in the same scan stops every helper that is still running again. Starts run
 * one at a time so that two carriers cannot both reach that path before either has reported back.
 */
public class AppZygoteStartGate(
    private val clock: () -> Long = SystemClock::elapsedRealtime,
) {
    private val operationMutex = Mutex()
    private val mutex = Mutex()
    private val activeLeaseCount = AtomicInteger()
    private var lastFailedStartAt: Long? = null

    /**
     * Runs an App Zygote lifecycle operation exclusively. Recovery uses this to prevent another
     * `useAppZygote` bind from cancelling ActivityManager's delayed zygote retirement.
     */
    public suspend fun <T> withExclusive(block: suspend () -> T): T =
        operationMutex.withLock { block() }

    /**
     * Runs [attempt], or returns [refused] without it when a carrier start has failed since
     * [scanStartedAt], the caller's scan start on the [SystemClock.elapsedRealtime] clock.
     *
     * [stoppedBeforeConnecting] tells from an attempt's result whether its binding died before the
     * service connected, which is how a client sees its app zygote fail to start.
     */
    public suspend fun <T> admit(
        scanStartedAt: Long,
        refused: () -> T,
        stoppedBeforeConnecting: (T) -> Boolean,
        attempt: suspend () -> T,
    ): T = operationMutex.withLock {
        admitExclusive(
            scanStartedAt = scanStartedAt,
            refused = refused,
            stoppedBeforeConnecting = stoppedBeforeConnecting,
            attempt = attempt,
        )
    }

    /** Runs a start while the caller already holds [withExclusive]. */
    public suspend fun <T> admitExclusive(
        scanStartedAt: Long,
        refused: () -> T,
        stoppedBeforeConnecting: (T) -> Boolean,
        attempt: suspend () -> T,
    ): T = mutex.withLock {
        val failedAt = lastFailedStartAt
        if (failedAt != null && failedAt >= scanStartedAt) {
            return@withLock refused()
        }
        val result = attempt()
        if (stoppedBeforeConnecting(result)) {
            lastFailedStartAt = clock()
        }
        result
    }

    /** Tracks a connected child that keeps the shared App Zygote alive. */
    public fun acquireLease(): Lease {
        activeLeaseCount.incrementAndGet()
        return Lease { activeLeaseCount.decrementAndGet() }
    }

    /** Waits until tracked `useAppZygote` services have disconnected. */
    public suspend fun awaitNoActiveLeases(
        timeoutMs: Long,
        pollIntervalMs: Long = 50L,
    ): Boolean {
        require(timeoutMs >= 0L)
        require(pollIntervalMs > 0L)
        return withTimeoutOrNull(timeoutMs) {
            while (activeLeaseCount.get() != 0) delay(pollIntervalMs)
            true
        } ?: false
    }

    public class Lease internal constructor(
        private val releaseAction: () -> Unit,
    ) {
        private val closed = AtomicBoolean(false)

        public fun close() {
            if (closed.compareAndSet(false, true)) releaseAction()
        }
    }

    public companion object {
        /** The gate that every app zygote carrier in this process goes through. */
        public val Default: AppZygoteStartGate = AppZygoteStartGate()
    }
}
