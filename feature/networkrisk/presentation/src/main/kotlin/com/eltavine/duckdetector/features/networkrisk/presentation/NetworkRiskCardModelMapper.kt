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
import com.eltavine.duckdetector.features.networkrisk.presentation.model.*

class NetworkRiskCardModelMapper {
    fun map(report: NetworkRiskReport): NetworkRiskCardModel {
        val window = report.network
        val hits = report.clients?.clients.orEmpty().count { it.state == ObservationState.OBSERVED }
        val probeErrors = report.stage == NetworkRiskStage.READY && report.hasProbeErrors()
        val warning = report.hasWarningEvidence()
        return NetworkRiskCardModel(
            title = "Network Risk",
            subtitle = "Network context, proxy configuration and client evidence",
            status = report.toDetectorStatus(),
            verdict = when {
                report.stage == NetworkRiskStage.LOADING -> "Scanning"
                report.stage == NetworkRiskStage.FAILED -> "Scan failed"
                warning && probeErrors -> "Network risk indicators observed; context incomplete"
                warning && window?.consistency == SampleConsistency.CHANGED -> "Network risk indicators observed; network changed during scan"
                warning -> "Network risk indicators observed"
                probeErrors -> "Network context incomplete"
                window?.consistency == SampleConsistency.CHANGED -> "Network changed during scan"
                else -> "Network context collected"
            },
            summary = when (report.stage) {
                NetworkRiskStage.LOADING -> "Collecting caller-visible evidence."
                NetworkRiskStage.FAILED -> report.errorMessage ?: "Collection failed."
                NetworkRiskStage.READY -> (if (probeErrors) "Some probes failed; available observations are retained. " else "") +
                    "Warnings highlight observed VPN/proxy configuration, client packages or module deployment traces for review. Legitimate VPNs and tests can trigger them; service activity and request routing remain unevaluated."
            },
            headerFacts = listOf(
                row("VPN transport", window?.vpnState() ?: ObservationState.UNAVAILABLE, "Visible networks only; this does not establish this app's request path.", warning = true),
                row("HTTP proxy", window?.stateFor(window.snapshot.defaultProxy.state) ?: ObservationState.UNAVAILABLE, "Configuration only.", warning = true),
                row("Client packages", report.clients?.state ?: ObservationState.UNAVAILABLE, "Exact package matches; installation does not establish service activity.", if (report.clients?.state == ObservationState.OBSERVED) hits.toString() else "Unknown", warning = hits > 0),
                row("Active tests", ObservationState.UNAVAILABLE, "Disabled; zero requests and zero bytes sent.", "Disabled"),
            ),
            sections = if (report.stage != NetworkRiskStage.READY) emptyList() else buildList {
                add(NetworkRiskSectionModel("networks", "Network context", window?.networkRows().orEmpty()))
                add(NetworkRiskSectionModel("proxy", "Proxy and DNS context", window?.proxyRows().orEmpty()))
                add(NetworkRiskSectionModel("clients", "Client packages", clientRows(report)))
                add(NetworkRiskSectionModel("modules", "Proxy module coverage", moduleRows(report)))
                add(NetworkRiskSectionModel("scan", "Scan summary", scanRows(report)))
            },
        )
    }

    private fun clientRows(report: NetworkRiskReport): List<NetworkRiskDetailRowModel> = buildList {
        val inventory = report.clients ?: return@buildList
        add(row("Package visibility", inventory.state,
            "${inventory.visibility}; calling user/profile only. Other users and work profiles are not queried. Not observed never means globally uninstalled.", inventory.visibility.name, failure = if (inventory.state == ObservationState.UNAVAILABLE) ProbeFailure.PLATFORM_FAILURE else null))
        inventory.clients.forEach { client ->
            val identity = when (client.identity) {
                ClientIdentity.SIGNATURE_VERIFIED -> "Signature verified against sampled upstream release key"
                ClientIdentity.IDENTITY_UNVERIFIED -> "Identity unverified"
            }
            add(row(client.displayName, client.state,
                "${client.packageName}; $identity; signature read: ${client.signingState.label}; ${client.signingFailure.describe()} version code: ${client.version ?: "unknown"}. Installed does not mean running.", failure = client.signingFailure, warning = true))
        }
    }

    private fun moduleRows(report: NetworkRiskReport): List<NetworkRiskDetailRowModel> = buildList {
        report.modules.forEach { module ->
            val name = when (module.deployment) {
                ProxyDeployment.BOX4MAGISK -> "Box4Magisk"
                ProxyDeployment.BOX_FOR_ROOT -> "Box for Root"
            }
            add(row("$name deployment trace", module.metadata.state,
                "Exact module.prop ID only; version ${module.metadata.value ?: "unknown"}. ${module.metadata.failure.describe()} Protected or renamed paths are outside coverage; metadata can be modified. Does not identify the running core or mechanism.", failure = module.metadata.failure, warning = true))
            add(row("$name service response", ObservationState.UNAVAILABLE, "Not probed. No ports scanned; changed ports and disabled control interfaces are outside coverage."))
            add(row("$name traffic effect", ObservationState.UNAVAILABLE, "Not evaluated. App exclusions and direct rules cannot be inferred from installation, TUN interfaces or service responses."))
        }
    }

    private fun scanRows(report: NetworkRiskReport): List<NetworkRiskDetailRowModel> = buildList {
        report.network?.let { window ->
            add(row("Sample consistency", if (window.consistency == SampleConsistency.REPEATED) ObservationState.OBSERVED else ObservationState.INCONCLUSIVE,
                "${window.attempts} adjacent comparisons; ${window.durationMs} ms; sample epoch ${window.startedAtEpochMs}. Repeated reads are not atomic and cannot exclude intermediate changes.",
                if (window.consistency == SampleConsistency.REPEATED) "Repeated sample" else "Inconclusive"))
        }
        add(row("Active protocol / DNS / egress tests", ObservationState.UNAVAILABLE,
            "Disabled. No endpoints, payloads, sockets or DNS requests; timeout not applicable; data budget 0 bytes, request budget 0."))
        add(row("Routing coverage", ObservationState.UNSUPPORTED,
            "No privileged firewall rules, other-UID process state, module logs or per-request traffic observation. Enterprise VPNs, local filters, DNS64/NAT64 and captive portals are legitimate contexts."))
        add(row("Export privacy", ObservationState.OBSERVED,
            "No interface names or network handles in export; no addresses, PAC URLs, DNS hostnames, subscriptions, credentials or connection history retained."))
    }
}
