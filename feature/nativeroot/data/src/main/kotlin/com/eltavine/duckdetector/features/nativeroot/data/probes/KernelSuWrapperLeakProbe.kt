package com.eltavine.duckdetector.features.nativeroot.data.probes

import com.eltavine.duckdetector.features.nativeroot.data.native.KernelSuWrapperLeakNativeBridge
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuWrapperLeakObservation
import com.eltavine.duckdetector.features.nativeroot.domain.WrapperLeakCollection
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.coroutineContext
import kotlinx.coroutines.ensureActive

/** Owns one bounded experiment for this scanner's lifetime, including concurrent/repeated scans. */
class KernelSuWrapperLeakProbe internal constructor(
    private val collect: () -> KernelSuWrapperLeakObservation,
) {
    constructor() : this(KernelSuWrapperLeakNativeBridge()::collect)
    private val admission = Mutex()
    private var cached: KernelSuWrapperLeakObservation? = null

    suspend fun collect(): KernelSuWrapperLeakObservation = admission.withLock {
        coroutineContext.ensureActive()
        cached?.let { return@withLock it }
        // Consume admission before entering collection: even an unexpected exception can occur
        // after a successful reopen. Only an explicit returned observation replaces this state.
        cached = KernelSuWrapperLeakObservation(
            collection = WrapperLeakCollection.UNAVAILABLE,
            detail = "A previous collection attempt did not return an observation; no retry is permitted for this scanner.",
        )
        val result = collect.invoke()
        cached = result
        coroutineContext.ensureActive()
        result
    }
}
