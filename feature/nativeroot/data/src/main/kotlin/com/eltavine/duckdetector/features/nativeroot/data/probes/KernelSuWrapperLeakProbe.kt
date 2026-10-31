package com.eltavine.duckdetector.features.nativeroot.data.probes

import com.eltavine.duckdetector.features.nativeroot.data.native.KernelSuWrapperLeakNativeBridge
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuWrapperLeakObservation
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.coroutineContext
import kotlinx.coroutines.ensureActive

/** Owns one bounded experiment for this detector's lifetime, including concurrent/repeated scans. */
class KernelSuWrapperLeakProbe internal constructor(
    private val collect: () -> KernelSuWrapperLeakObservation,
) {
    constructor() : this(KernelSuWrapperLeakNativeBridge()::collect)
    private val admission = Mutex()
    private var cached: KernelSuWrapperLeakObservation? = null

    suspend fun collect(): KernelSuWrapperLeakObservation = admission.withLock {
        coroutineContext.ensureActive()
        cached?.let { return@withLock it }
        // Cache before observing cancellation: an interrupted caller must not repeat the stimulus.
        val result = collect.invoke()
        cached = result
        coroutineContext.ensureActive()
        result
    }
}
