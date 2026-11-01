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

import com.eltavine.duckdetector.capability.systemproperties.data.readJvmProperty
import com.eltavine.duckdetector.features.networkrisk.domain.*

/** Raw host lives only in the repeated sample; reports retain state, port and comparison. */
internal data class JvmHttpProxyValues(val host: String?, val port: String?) {
    fun project(): NetworkObservation<Int> {
        if (host.isNullOrEmpty() && port.isNullOrEmpty()) return NetworkObservation.absent()
        val number = port?.toIntOrNull()
        return if (!host.isNullOrBlank() && number != null && number in 1..65535) NetworkObservation.observed(number)
        else NetworkObservation(ObservationState.INCONCLUSIVE)
    }
}

internal fun readJvmHttpProxy(
    read: (String) -> Result<String?> = ::readJvmProperty,
): NetworkObservation<JvmHttpProxyValues> {
    val host = read("http.proxyHost")
    val port = read("http.proxyPort")
    val failures = listOfNotNull(host.exceptionOrNull(), port.exceptionOrNull())
    return when {
        failures.any { it is SecurityException } -> NetworkObservation(ObservationState.PERMISSION_LIMITED, failure = ProbeFailure.ACCESS_DENIED)
        failures.isNotEmpty() -> NetworkObservation.unavailable(ProbeFailure.PLATFORM_FAILURE)
        else -> NetworkObservation.observed(JvmHttpProxyValues(host.getOrNull(), port.getOrNull()))
    }
}

internal fun NetworkObservation<JvmHttpProxyValues>.project(): NetworkObservation<Int> =
    value?.project() ?: NetworkObservation(state, failure = failure)
