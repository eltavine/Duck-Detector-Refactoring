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

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind

/** Observation state alone describes coverage; severity also needs the signal's meaning. */
fun ObservationState.toDetectorStatus(failure: ProbeFailure? = null): DetectorStatus = DetectorStatus.info(
    if (failure.isProbeError()) InfoKind.ERROR else InfoKind.SUPPORT,
)

fun NetworkRiskReport.toDetectorStatus(): DetectorStatus = when {
    stage == NetworkRiskStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
    hasWarningEvidence() -> DetectorStatus.warning()
    stage == NetworkRiskStage.READY && hasProbeErrors() -> DetectorStatus.info(InfoKind.ERROR)
    else -> DetectorStatus.info(InfoKind.SUPPORT)
}

/** Warning identifies configuration or installation evidence, never service activity or traffic use. */
fun NetworkRiskReport.hasWarningEvidence(): Boolean = stage == NetworkRiskStage.READY && (
    network?.hasWarningEvidence() == true ||
        clients?.clients.orEmpty().any { it.state == ObservationState.OBSERVED } ||
        modules.any { it.metadata.state == ObservationState.OBSERVED }
    )

private fun NetworkSampleWindow.hasWarningEvidence(): Boolean = consistency == SampleConsistency.REPEATED && (
    vpnState() == ObservationState.OBSERVED ||
        snapshot.defaultProxy.state == ObservationState.OBSERVED ||
        snapshot.proxySources?.jvmHttpProxy?.state == ObservationState.OBSERVED ||
        snapshot.visibleNetworks.state == ObservationState.OBSERVED && snapshot.visibleNetworks.value.orEmpty().any {
            it.link.state == ObservationState.OBSERVED && it.link.value?.proxy != null
        }
    )

fun NetworkSampleWindow.vpnState(): ObservationState {
    val networks = snapshot.visibleNetworks
    val state = when {
        networks.state != ObservationState.OBSERVED -> networks.state
        networks.value.orEmpty().any {
            it.transports.state == ObservationState.OBSERVED && NetworkTransport.VPN in it.transports.value.orEmpty()
        } -> ObservationState.OBSERVED
        else -> networks.value.orEmpty().firstOrNull { it.transports.state != ObservationState.OBSERVED }?.transports?.state
            ?: ObservationState.NOT_OBSERVED
    }
    return stateFor(state)
}

/** Collectors retain failures as values, so READY describes completion, not successful coverage. */
fun NetworkRiskReport.hasProbeErrors(): Boolean =
    network?.snapshot?.hasProbeErrors() == true || clients?.state == ObservationState.UNAVAILABLE ||
        clients?.clients.orEmpty().any { it.signingFailure.isProbeError() } ||
        modules.any { it.metadata.failure.isProbeError() }

private fun NetworkSnapshot.hasProbeErrors(): Boolean =
    listOf(defaultNetwork, boundNetwork, defaultProxy, visibleNetworks).any { it.failure.isProbeError() } ||
        proxySources?.jvmHttpProxy?.failure.isProbeError() || visibleNetworks.value.orEmpty().any {
            it.transports.failure.isProbeError() || it.link.failure.isProbeError()
        }

private fun ProbeFailure?.isProbeError(): Boolean = when (this) {
    ProbeFailure.PLATFORM_FAILURE, ProbeFailure.READ_LIMIT, ProbeFailure.INVALID_METADATA,
    ProbeFailure.DISAPPEARED -> true
    ProbeFailure.ACCESS_DENIED, ProbeFailure.NOT_EVALUATED, null -> false
}

/** A changing sample cannot support correlations, including an assertion of absence. */
fun NetworkSampleWindow.stateFor(state: ObservationState): ObservationState = when {
    consistency == SampleConsistency.CHANGED &&
        state in setOf(ObservationState.OBSERVED, ObservationState.NOT_OBSERVED) -> ObservationState.INCONCLUSIVE
    else -> state
}
