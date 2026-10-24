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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import com.eltavine.duckdetector.features.nativeroot.data.native.KernelSuTimingWindow
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingAnalysis
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingClassifier
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreAttempt
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreStatus
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingObservation
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingPreflight
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingPreflightStatus
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingProfile
import kotlinx.coroutines.CancellationException
import com.eltavine.duckdetector.core.platform.PlatformFailureName

internal interface KernelSuTimingBackend {
    fun supported(): Boolean
    fun interactive(): Boolean
    fun cpus(): List<Int>
    fun sample(cpu: Int, preflight: Boolean): KernelSuTimingWindow
    fun elapsedMillis(): Long
}

internal class KernelSuTimingExperiment(private val backend: KernelSuTimingBackend) {
    fun collect(cancelled: () -> Boolean): KernelSuTimingObservation {
        var observation = KernelSuTimingObservation(cleanupCompleted = true)
        val started = backend.elapsedMillis()
        fun stop(): KernelSuTimingCollection? = when {
            cancelled() -> KernelSuTimingCollection.CANCELLED
            backend.elapsedMillis() - started >= 40_000 -> KernelSuTimingCollection.TIMED_OUT
            !backend.interactive() -> KernelSuTimingCollection.NONINTERACTIVE
            else -> null
        }
        try {
            if (!backend.supported()) return observation.copy(collection = KernelSuTimingCollection.UNSUPPORTED)
            stop()?.let { return observation.copy(collection = it) }
            observation = observation.copy(cleanupCompleted = false)
            val preflightWindow = backend.sample(-1, true)
            observation = observation.copy(cleanupCompleted = preflightWindow.cleanup,
                counterFrequencyHz = preflightWindow.frequency)
            if (preflightWindow.status != KernelSuTimingCoreStatus.MEASURED || !preflightWindow.cleanup) {
                return observation.copy(collection = if (preflightWindow.status == null)
                    KernelSuTimingCollection.UNSUPPORTED else KernelSuTimingCollection.UNAVAILABLE,
                    detail = "Preflight sampling failed: ${preflightWindow.status}")
            }
            val frequencies = preflightWindow.vectors.single().groupingBy { it }.eachCount()
                .flatMap { (ticks, count) -> listOf(ticks, count.toULong()) }
            observation = observation.copy(preflight = KernelSuTimingPreflight.fromFrequencies(frequencies))
            stop()?.let { return observation.copy(collection = it) }
            if (observation.preflight.status != KernelSuTimingPreflightStatus.ACCEPTED) {
                return observation.copy(collection = KernelSuTimingCollection.PREFLIGHT_REJECTED)
            }
            observation = observation.copy(enumeratedCpus = backend.cpus())
            if (observation.enumeratedCpus.isEmpty()) return observation.copy(collection = KernelSuTimingCollection.UNAVAILABLE)
            for (cpu in observation.enumeratedCpus) {
                val rounds = mutableListOf<KernelSuTimingAnalysis>()
                var attempt = KernelSuTimingCoreAttempt(cpu, null, KernelSuTimingCoreStatus.SAMPLING_FAILED)
                for (round in 0 until KernelSuTimingProfile.REQUIRED_ROUNDS) {
                    stop()?.let { return observation.copy(collection = it) }
                    observation = observation.copy(cleanupCompleted = false)
                    val window = backend.sample(cpu, false)
                    observation = observation.copy(cleanupCompleted = window.cleanup)
                    val status = when {
                        !window.cleanup -> KernelSuTimingCoreStatus.CLEANUP_FAILED
                        window.status != KernelSuTimingCoreStatus.MEASURED ->
                            window.status ?: KernelSuTimingCoreStatus.SAMPLING_FAILED
                        window.frequency != observation.counterFrequencyHz || window.frequency == 0uL ->
                            KernelSuTimingCoreStatus.TIMER_UNAVAILABLE
                        window.actualCpu != cpu && window.status == KernelSuTimingCoreStatus.MEASURED ->
                            KernelSuTimingCoreStatus.CPU_MISMATCH
                        else -> window.status ?: KernelSuTimingCoreStatus.SAMPLING_FAILED
                    }
                    if (status == KernelSuTimingCoreStatus.MEASURED) {
                        rounds += KernelSuTimingClassifier.summarize(window.vectors)
                    }
                    attempt = KernelSuTimingCoreAttempt(cpu, window.actualCpu, status, rounds.toList())
                    observation = observation.copy(attempts = observation.attempts.filterNot { it.requestedCpu == cpu } + attempt)
                    stop()?.let { return observation.copy(collection = it) }
                    if (!window.cleanup) return observation.copy(collection = KernelSuTimingCollection.PARTIAL)
                    if (status != KernelSuTimingCoreStatus.MEASURED || !rounds.last().matched) break
                }
                if (attempt.confirmed) return observation.copy(collection = KernelSuTimingCollection.COLLECTED)
            }
            return observation.copy(collection = if (observation.attempts.all { it.completed })
                KernelSuTimingCollection.COLLECTED else KernelSuTimingCollection.PARTIAL)
        } catch (failure: Exception) {
            if (failure is CancellationException) throw failure
            return observation.copy(collection = KernelSuTimingCollection.UNAVAILABLE,
                detail = PlatformFailureName.describe(failure))
        }
    }
}
