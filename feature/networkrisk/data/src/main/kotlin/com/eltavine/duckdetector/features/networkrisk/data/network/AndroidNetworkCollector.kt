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

package com.eltavine.duckdetector.features.networkrisk.data.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.ProxyInfo
import android.net.Uri
import android.os.SystemClock
import com.eltavine.duckdetector.features.networkrisk.domain.*
import java.net.Inet4Address
import java.net.Inet6Address

private typealias RawNetworks = Map<Network, Pair<NetworkObservation<NetworkCapabilities>, NetworkObservation<LinkProperties>>>

/** Raw framework values live only during adjacent comparisons, never in exported evidence. */
internal class AndroidNetworkCollector(context: Context) {
    private val manager = context.getSystemService(ConnectivityManager::class.java)

    fun collect(): NetworkSampleWindow {
        val epoch = System.currentTimeMillis()
        val start = SystemClock.elapsedRealtime()
        val sampled = RepeatedNetworkSampler(::read).collect()
        val raw = sampled.value
        return NetworkSampleWindow(
            snapshot = NetworkSnapshot(
                defaultNetwork = raw.defaultNetwork.map { it.networkHandle },
                boundNetwork = raw.boundNetwork.map { it.networkHandle },
                defaultProxy = raw.defaultProxy.map { it.toConfiguration() },
                proxySources = ProxySourceCheck(
                    jvmHttpProxy = raw.jvmProxy.project(),
                    comparison = compareProxySources(
                        raw.defaultProxy.map { it.toConfiguration() }, raw.jvmProxy.project(),
                        sameEndpoint = raw.defaultProxy.value?.host?.equals(raw.jvmProxy.value?.host, ignoreCase = true) == true &&
                            raw.defaultProxy.value?.port == raw.jvmProxy.value?.port?.toIntOrNull(),
                    ),
                ),
                visibleNetworks = raw.networks.map { networks -> networks.map { (network, properties) ->
                    VisibleNetwork(network.networkHandle, properties.first.map { it.transports() }, properties.second.map { it.toContext() })
                } },
            ),
            consistency = if (sampled.repeated) SampleConsistency.REPEATED else SampleConsistency.CHANGED,
            startedAtEpochMs = epoch,
            durationMs = SystemClock.elapsedRealtime() - start,
            attempts = sampled.attempts,
        )
    }

    private data class RawSnapshot(
        val defaultNetwork: NetworkObservation<Network>,
        val boundNetwork: NetworkObservation<Network>,
        val defaultProxy: NetworkObservation<ProxyInfo>,
        val networks: NetworkObservation<RawNetworks>,
        val jvmProxy: NetworkObservation<JvmHttpProxyValues>,
    )

    @Suppress("DEPRECATION")
    private fun read(): RawSnapshot {
        val default = query { manager?.activeNetwork }
        val bound = query { manager?.boundNetworkForProcess }
        val proxy = query { manager?.defaultProxy }
        val jvmProxy = readJvmHttpProxy()
        val networks: NetworkObservation<RawNetworks> = query {
            manager?.allNetworks?.toSet()?.plus(listOfNotNull(default.value, bound.value))
        }.let { result ->
            if ((result.value?.size ?: 0) > 32) {
                NetworkObservation.unavailable(ProbeFailure.READ_LIMIT)
            } else result.map { networks ->
                networks.associateWith { network ->
                    query { manager?.getNetworkCapabilities(network)?.let(::NetworkCapabilities) }.missingNetwork() to
                        query { manager?.getLinkProperties(network) }.missingNetwork()
                }
            }
        }
        return RawSnapshot(default, bound, proxy, networks, jvmProxy)
    }

    private fun <T> query(block: () -> T?): NetworkObservation<T> {
        if (manager == null) return NetworkObservation.unavailable(ProbeFailure.PLATFORM_FAILURE)
        return try {
            block()?.let { NetworkObservation.observed(it) } ?: NetworkObservation.absent()
        } catch (_: SecurityException) {
            NetworkObservation(ObservationState.PERMISSION_LIMITED, failure = ProbeFailure.ACCESS_DENIED)
        } catch (_: RuntimeException) {
            NetworkObservation.unavailable(ProbeFailure.PLATFORM_FAILURE)
        }
    }

    private fun <T> NetworkObservation<T>.missingNetwork(): NetworkObservation<T> =
        if (state == ObservationState.NOT_OBSERVED) NetworkObservation.unavailable(ProbeFailure.DISAPPEARED) else this
}

internal fun <T, R> NetworkObservation<T>.map(transform: (T) -> R): NetworkObservation<R> =
    NetworkObservation(state, value?.let(transform), failure)

internal fun ProxyInfo.toConfiguration(): ProxyConfiguration = ProxyConfiguration(
    kind = if (pacFileUrl != null && pacFileUrl != Uri.EMPTY) ProxyKind.PAC else ProxyKind.STATIC,
    port = port,
    exclusionCount = exclusionList?.size ?: 0,
)

private fun NetworkCapabilities.transports(): Set<NetworkTransport> = buildSet {
    if (hasTransport(NetworkCapabilities.TRANSPORT_VPN)) add(NetworkTransport.VPN)
    if (hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) add(NetworkTransport.WIFI)
    if (hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) add(NetworkTransport.CELLULAR)
    if (hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) add(NetworkTransport.ETHERNET)
    if (hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) add(NetworkTransport.BLUETOOTH)
    if (isEmpty()) add(NetworkTransport.OTHER)
}

private fun LinkProperties.toContext(): LinkContext = LinkContext(
    interfaceName = interfaceName,
    routes = routes.map { route ->
        VisibleRoute(
            family = when (route.destination.address) {
                is Inet4Address -> AddressFamily.IPV4
                is Inet6Address -> AddressFamily.IPV6
                else -> AddressFamily.OTHER
            },
            prefixLength = route.destination.prefixLength,
            defaultRoute = route.isDefaultRoute,
            hasGateway = route.hasGateway(),
        )
    },
    proxy = httpProxy?.toConfiguration(),
    privateDnsActive = isPrivateDnsActive,
    strictPrivateDns = privateDnsServerName != null,
    dnsServerCount = dnsServers.size,
)
