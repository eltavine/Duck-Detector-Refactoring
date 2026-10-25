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

import com.eltavine.duckdetector.core.platform.PlatformFailureName
import com.eltavine.duckdetector.features.nativeroot.data.native.KernelSuTimingWindow
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingAnalysis
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingClassifier
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreAttempt
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreStatus
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCpuSnapshot
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingObservation
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingPreflight
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingPreflightStatus
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingProfile
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingWindowEvidence
import kotlinx.coroutines.CancellationException

internal interface KernelSuTimingBackend {
    fun supported(): Boolean
    fun interactive(): Boolean
    fun cpuSnapshot(): KernelSuTimingCpuSnapshot
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
        fun finish(state: KernelSuTimingCollection): KernelSuTimingObservation = observation.copy(
            collection = state, finalCpus = backend.cpuSnapshot())
        try {
            if (!backend.supported()) return observation.copy(collection = KernelSuTimingCollection.UNSUPPORTED)
            stop()?.let { return finish(it) }
            observation = observation.copy(initialCpus = backend.cpuSnapshot())
            val initial = observation.initialCpus
            if (!initial.complete || initial.present.isNullOrEmpty()) return finish(KernelSuTimingCollection.UNAVAILABLE)
            val present = initial.present.orEmpty()
            for (cpu in present.take(KernelSuTimingProfile.MAXIMUM_CORES)) {
                if (cpu !in initial.eligible) continue
                val rounds = mutableListOf<KernelSuTimingAnalysis>()
                val windows = mutableListOf<KernelSuTimingWindowEvidence>()
                var preflight = KernelSuTimingPreflight()
                for (index in 0..KernelSuTimingProfile.REQUIRED_ROUNDS) {
                    stop()?.let { return finish(it) }
                    val before = backend.cpuSnapshot()
                    val window = if (cpu in before.eligible && before.complete &&
                        (windows.isEmpty() || windows.first().before == before)) {
                        observation = observation.copy(cleanupCompleted = false)
                        backend.sample(cpu, index == 0)
                    } else KernelSuTimingWindow(KernelSuTimingCoreStatus.ELIGIBILITY_CHANGED, null,
                        0uL, true, emptyList(), emptyList(), emptyList())
                    observation = observation.copy(cleanupCompleted = window.cleanup)
                    val evidence = KernelSuTimingWindowEvidence(before, backend.cpuSnapshot(),
                        window.allowedCpus, window.outcomes, window.frequency)
                    windows += evidence
                    var status = when {
                        !window.cleanup -> KernelSuTimingCoreStatus.CLEANUP_FAILED
                        window.status != KernelSuTimingCoreStatus.MEASURED ->
                            window.status ?: KernelSuTimingCoreStatus.SAMPLING_FAILED
                        window.actualCpu != cpu -> KernelSuTimingCoreStatus.CPU_MISMATCH
                        !evidence.stable || cpu !in evidence.before.eligible -> KernelSuTimingCoreStatus.ELIGIBILITY_CHANGED
                        window.frequency == 0uL || window.frequency != windows.first().counterFrequencyHz ->
                            KernelSuTimingCoreStatus.TIMER_UNAVAILABLE
                        !evidence.expectedOutcomes -> KernelSuTimingCoreStatus.OUTCOME_CONTAMINATED
                        else -> KernelSuTimingCoreStatus.MEASURED
                    }
                    if (index == 0 && window.status == KernelSuTimingCoreStatus.MEASURED) {
                        val frequencies = window.vectors.single().groupingBy { it }.eachCount()
                            .flatMap { (ticks, count) -> listOf(ticks, count.toULong()) }
                        preflight = KernelSuTimingPreflight.fromFrequencies(frequencies)
                        if (status == KernelSuTimingCoreStatus.MEASURED &&
                            preflight.status != KernelSuTimingPreflightStatus.ACCEPTED) {
                            status = KernelSuTimingCoreStatus.PREFLIGHT_REJECTED
                        }
                    } else if (index > 0 && status == KernelSuTimingCoreStatus.MEASURED) {
                        val analysis = KernelSuTimingClassifier.summarize(window.vectors)
                        rounds += analysis
                        if (!analysis.valid) status = KernelSuTimingCoreStatus.INSUFFICIENT_SUPPORT
                    }
                    val attempt = KernelSuTimingCoreAttempt(cpu, window.actualCpu, status,
                        rounds.toList(), preflight, windows.toList())
                    observation = observation.copy(attempts = observation.attempts.filterNot { it.requestedCpu == cpu } + attempt)
                    stop()?.let { return finish(it) }
                    if (!window.cleanup) return finish(KernelSuTimingCollection.PARTIAL)
                    if (status != KernelSuTimingCoreStatus.MEASURED || (index > 0 && !rounds.last().matched)) break
                }
                if (observation.attempts.last().confirmed) return finish(KernelSuTimingCollection.COLLECTED)
            }
            val finished = finish(KernelSuTimingCollection.PARTIAL)
            val complete = finished.coverageStable && finished.attempts.all { it.completed } &&
                finished.attempts.map { it.requestedCpu } == initial.present
            return finished.copy(collection = if (complete) KernelSuTimingCollection.COLLECTED
                else KernelSuTimingCollection.PARTIAL)
        } catch (failure: Exception) {
            if (failure is CancellationException) throw failure
            return observation.copy(collection = KernelSuTimingCollection.UNAVAILABLE,
                detail = PlatformFailureName.describe(failure).take(160))
        }
    }
}
