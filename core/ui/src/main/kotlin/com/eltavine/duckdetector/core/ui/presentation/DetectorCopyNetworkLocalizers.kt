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

package com.eltavine.duckdetector.core.ui.presentation

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.eltavine.duckdetector.core.ui.R

private val networkIndexedRowLabel = Regex("""^Network (\d+) (transports|interface / routes|link proxy / PAC|Private DNS)$""")

private val networkModuleRowLabel = Regex("""^(Box4Magisk|Box for Root) (deployment trace|service response|traffic effect)$""")

private val networkStateLocalHandle = Regex("""^(Observed|Not observed|Unavailable|Permission limited|Unsupported|Inconclusive) \(local handle (\d+)\)$""")

private val networkStateReturnedCount = Regex("""^(Observed|Not observed|Unavailable|Permission limited|Unsupported|Inconclusive); (\d+) returned$""")

private val networkStatePort = Regex("""^(Observed|Not observed|Unavailable|Permission limited|Unsupported|Inconclusive); port (\d+)$""")

private val networkStateSuffix = Regex("""^(Observed|Not observed|Unavailable|Permission limited|Unsupported|Inconclusive); (.+)$""")

private val networkRouteSummary = Regex("""^(\d+) routes \(IPv4 (\d+), IPv6 (\d+), default (\d+)\)$""")

@Composable
internal fun localizeNetworkSummary(text: String): String? {
    networkStateLocalHandle.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_value_network_local_handle,
            localizeDetectorCopy(match.groupValues[1]),
            match.groupValues[2],
        )
    }
    networkStateReturnedCount.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_value_network_returned_count,
            localizeDetectorCopy(match.groupValues[1]),
            match.groupValues[2].toInt(),
        )
    }
    networkStatePort.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_value_network_port,
            localizeDetectorCopy(match.groupValues[1]),
            match.groupValues[2].toInt(),
        )
    }
    networkStateSuffix.matchEntire(text)?.let { match ->
        val localizedParts = mutableListOf<String>()
        for (part in match.groupValues[2].split("; ")) {
            val route = networkRouteSummary.matchEntire(part)
            localizedParts += if (route == null) {
                part
            } else {
                stringResource(
                    R.string.detector_copy_value_network_routes,
                    route.groupValues[1].toInt(),
                    route.groupValues[2].toInt(),
                    route.groupValues[3].toInt(),
                    route.groupValues[4].toInt(),
                )
            }
        }
        val localizedSuffix = localizedParts.joinToString("; ")
        return "${localizeDetectorCopy(match.groupValues[1])}; $localizedSuffix"
    }
    networkIndexedRowLabel.matchEntire(text)?.let { match ->
        val resource = when (match.groupValues[2]) {
            "transports" -> R.string.detector_copy_label_network_transports
            "interface / routes" -> R.string.detector_copy_label_network_interface_routes
            "link proxy / PAC" -> R.string.detector_copy_label_network_link_proxy
            "Private DNS" -> R.string.detector_copy_label_network_private_dns
            else -> return text
        }
        return stringResource(resource, match.groupValues[1].toInt())
    }
    networkModuleRowLabel.matchEntire(text)?.let { match ->
        val resource = when (match.groupValues[2]) {
            "deployment trace" -> R.string.detector_copy_label_network_module_deployment
            "service response" -> R.string.detector_copy_label_network_module_service
            "traffic effect" -> R.string.detector_copy_label_network_module_traffic
            else -> return text
        }
        return stringResource(resource, match.groupValues[1])
    }
    return null
}
