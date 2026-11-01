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

package com.eltavine.duckdetector.features.networkrisk.presentation

import com.eltavine.duckdetector.features.networkrisk.domain.*
import com.eltavine.duckdetector.features.networkrisk.presentation.model.NetworkRiskDetailRowModel

internal fun NetworkSampleWindow.networkRows(): List<NetworkRiskDetailRowModel> = buildList {
    val data = snapshot
    add(row("Caller default network", stateFor(data.defaultNetwork.state),
        "Calling UID scope. A null result can mean disconnected or blocked. ${data.defaultNetwork.failure.describe()}",
        data.defaultNetwork.value?.let { "${stateFor(data.defaultNetwork.state).label} (local handle $it)" }
            ?: stateFor(data.defaultNetwork.state).label, failure = data.defaultNetwork.failure).copy(exportValue = stateFor(data.defaultNetwork.state).label))
    add(row("Process binding", stateFor(data.boundNetwork.state),
        "Explicit process binding only; unbound does not mean offline. ${data.boundNetwork.failure.describe()}",
        data.boundNetwork.value?.let { "${stateFor(data.boundNetwork.state).label} (local handle $it)" }
            ?: stateFor(data.boundNetwork.state).label, failure = data.boundNetwork.failure).copy(exportValue = stateFor(data.boundNetwork.state).label))
    add(row("Visible networks", stateFor(data.visibleNetworks.state),
        "Framework-visible handles only; not every UID, profile, socket or kernel routing table. ${data.visibleNetworks.failure.describe()}",
        "${stateFor(data.visibleNetworks.state).label}; ${data.visibleNetworks.value?.size ?: 0} returned", failure = data.visibleNetworks.failure))
    data.visibleNetworks.value.orEmpty().forEachIndexed { index, network ->
        val roles = buildList {
            if (network.handle == data.defaultNetwork.value) add("caller default")
            if (network.handle == data.boundNetwork.value) add("process bound")
        }.joinToString(", ").ifEmpty { "other visible" }
        add(row("Network ${index + 1} transports", stateFor(network.transports.state),
            "$roles; ${network.transports.failure.describe()} VPN transport does not establish proxying of this app's requests.",
            "${stateFor(network.transports.state).label}; ${network.transports.value?.sortedBy { it.ordinal }?.joinToString { it.name } ?: "unknown"}",
            failure = network.transports.failure, warning = data.visibleNetworks.state == ObservationState.OBSERVED && NetworkTransport.VPN in network.transports.value.orEmpty()))
        val link = network.link.value
        add(row("Network ${index + 1} interface / routes", stateFor(network.link.state),
            "$roles; LinkProperties routes only; addresses and gateways omitted. ${network.link.failure.describe()}",
            if (link == null) stateFor(network.link.state).label else "${stateFor(network.link.state).label}; ${link.interfaceName ?: "unnamed"}; ${link.routes.describeRoutes()}", failure = network.link.failure)
            .copy(exportValue = if (link == null) stateFor(network.link.state).label else "${stateFor(network.link.state).label}; ${link.routes.describeRoutes()}"))
    }
}

internal fun NetworkSampleWindow.proxyRows(): List<NetworkRiskDetailRowModel> = buildList {
    add(row("Default HTTP proxy", stateFor(snapshot.defaultProxy.state),
        "Global proxy takes precedence, then the process-bound network, otherwise the calling UID's network. Configuration is not actual request use. ${snapshot.defaultProxy.value?.describe() ?: snapshot.defaultProxy.failure.describe()}", failure = snapshot.defaultProxy.failure, warning = true))
    snapshot.proxySources?.let { sources ->
        add(row("JVM HTTP proxy", stateFor(sources.jvmHttpProxy.state),
            "Process-local http.proxyHost/http.proxyPort only; host omitted. Partial or invalid pairs are inconclusive; exclusions, HTTPS/SOCKS and custom ProxySelectors are outside this check. ${sources.jvmHttpProxy.failure.describe()}",
            value = stateFor(sources.jvmHttpProxy.state).label + (sources.jvmHttpProxy.value?.let { "; port $it" } ?: ""), failure = sources.jvmHttpProxy.failure, warning = true))
        val state = stateFor(sources.comparison.toObservationState())
        add(row("Proxy source cross-check", state,
            "ConnectivityManager and JVM static HTTP endpoint views; correlated sources, not independent evidence of traffic use. Process overrides and asynchronous updates can differ.",
            value = if (consistency == SampleConsistency.CHANGED) "Inconclusive" else when (sources.comparison) {
                ProxySourceComparison.ALIGNED -> "Aligned"
                ProxySourceComparison.DIFFERENT -> "Inconclusive: views differ"
                ProxySourceComparison.PAC_NOT_COMPARABLE -> "Not comparable: PAC"
                ProxySourceComparison.SOURCE_UNAVAILABLE -> "Not comparable: source unavailable"
            }))
    }
    snapshot.visibleNetworks.value.orEmpty().forEachIndexed { index, network ->
        val link = network.link.value
        val proxyState = if (link == null) network.link.state else if (link.proxy == null) ObservationState.NOT_OBSERVED else ObservationState.OBSERVED
        add(row("Network ${index + 1} link proxy / PAC", stateFor(proxyState),
            link?.proxy?.describe() ?: "Network-specific configuration only; no PAC fetch or request performed. ${network.link.failure.describe()}",
            failure = network.link.failure, warning = snapshot.visibleNetworks.state == ObservationState.OBSERVED && network.link.state == ObservationState.OBSERVED))
        val dnsState = if (link == null) network.link.state else if (link.privateDnsActive) ObservationState.OBSERVED else ObservationState.NOT_OBSERVED
        add(row("Network ${index + 1} Private DNS", stateFor(dnsState),
            if (link == null) network.link.failure.describe() else "Context only; not proxy evidence. Strict name configured: ${link.strictPrivateDns}; DNS servers: ${link.dnsServerCount}; names and addresses omitted.", failure = network.link.failure))
    }
}

private fun List<VisibleRoute>.describeRoutes(): String =
    "${size} routes (IPv4 ${count { it.family == AddressFamily.IPV4 }}, IPv6 ${count { it.family == AddressFamily.IPV6 }}, default ${count { it.defaultRoute }})"
