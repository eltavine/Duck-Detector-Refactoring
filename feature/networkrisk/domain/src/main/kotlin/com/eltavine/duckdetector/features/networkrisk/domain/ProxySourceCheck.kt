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

package com.eltavine.duckdetector.features.networkrisk.domain

enum class ProxySourceComparison { ALIGNED, DIFFERENT, PAC_NOT_COMPARABLE, SOURCE_UNAVAILABLE }
data class ProxySourceCheck(
    val jvmHttpProxy: NetworkObservation<Int>,
    val comparison: ProxySourceComparison,
)

/** Compares static endpoint views only; synchronization delay or process overrides can differ. */
fun compareProxySources(
    framework: NetworkObservation<ProxyConfiguration>,
    jvm: NetworkObservation<Int>,
    sameEndpoint: Boolean,
): ProxySourceComparison = when {
    framework.value?.kind == ProxyKind.PAC -> ProxySourceComparison.PAC_NOT_COMPARABLE
    framework.state !in comparableStates || jvm.state !in comparableStates -> ProxySourceComparison.SOURCE_UNAVAILABLE
    framework.state == ObservationState.NOT_OBSERVED && jvm.state == ObservationState.NOT_OBSERVED -> ProxySourceComparison.ALIGNED
    framework.state == jvm.state && sameEndpoint -> ProxySourceComparison.ALIGNED
    else -> ProxySourceComparison.DIFFERENT
}

fun ProxySourceComparison.toObservationState(): ObservationState = when (this) {
    ProxySourceComparison.ALIGNED -> ObservationState.OBSERVED
    ProxySourceComparison.DIFFERENT, ProxySourceComparison.SOURCE_UNAVAILABLE -> ObservationState.INCONCLUSIVE
    ProxySourceComparison.PAC_NOT_COMPARABLE -> ObservationState.UNSUPPORTED
}

private val comparableStates = setOf(ObservationState.OBSERVED, ObservationState.NOT_OBSERVED)
