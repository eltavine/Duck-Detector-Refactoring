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

enum class ObservationState { OBSERVED, NOT_OBSERVED, UNAVAILABLE, PERMISSION_LIMITED, UNSUPPORTED, INCONCLUSIVE }
enum class ProbeFailure { ACCESS_DENIED, PLATFORM_FAILURE, DISAPPEARED, READ_LIMIT, INVALID_METADATA, NOT_EVALUATED }

/** Absence is scoped to this probe; a missing value never implies a device-wide absence. */
data class NetworkObservation<out T>(
    val state: ObservationState,
    val value: T? = null,
    val failure: ProbeFailure? = null,
) {
    companion object {
        fun <T> observed(value: T): NetworkObservation<T> = NetworkObservation(ObservationState.OBSERVED, value)
        fun <T> absent(): NetworkObservation<T> = NetworkObservation(ObservationState.NOT_OBSERVED)
        fun <T> unavailable(failure: ProbeFailure): NetworkObservation<T> = NetworkObservation(ObservationState.UNAVAILABLE, failure = failure)
    }
}

enum class NetworkTransport { VPN, WIFI, CELLULAR, ETHERNET, BLUETOOTH, OTHER }
enum class ProxyKind { STATIC, PAC }
data class ProxyConfiguration(val kind: ProxyKind, val port: Int, val exclusionCount: Int)
enum class AddressFamily { IPV4, IPV6, OTHER }
data class VisibleRoute(val family: AddressFamily, val prefixLength: Int, val defaultRoute: Boolean, val hasGateway: Boolean)
data class LinkContext(
    val interfaceName: String?,
    val routes: List<VisibleRoute>,
    val proxy: ProxyConfiguration?,
    val privateDnsActive: Boolean,
    val strictPrivateDns: Boolean,
    val dnsServerCount: Int,
)
data class VisibleNetwork(
    val handle: Long,
    val transports: NetworkObservation<Set<NetworkTransport>>,
    val link: NetworkObservation<LinkContext>,
)
data class NetworkSnapshot(
    val defaultNetwork: NetworkObservation<Long>,
    val boundNetwork: NetworkObservation<Long>,
    val defaultProxy: NetworkObservation<ProxyConfiguration>,
    val visibleNetworks: NetworkObservation<List<VisibleNetwork>>,
    val proxySources: ProxySourceCheck? = null,
)
enum class SampleConsistency { REPEATED, CHANGED }
data class NetworkSampleWindow(
    val snapshot: NetworkSnapshot,
    val consistency: SampleConsistency,
    val startedAtEpochMs: Long,
    val durationMs: Long,
    val attempts: Int,
)
