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

package com.eltavine.duckdetector.features.adbruntime.data.repository

import com.eltavine.duckdetector.features.adbruntime.domain.AdbMdnsServiceKind
import com.eltavine.duckdetector.features.adbruntime.domain.AdbMdnsSnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProbeState

internal val AdbMdnsServiceKind.serviceType: String
    get() = when (this) {
        AdbMdnsServiceKind.LEGACY_TCP -> "_adb._tcp"
        AdbMdnsServiceKind.TLS_CONNECT -> "_adb-tls-connect._tcp"
    }

/**
 * What one discovery window learned about each ADB service type, in [kinds]' priority order.
 *
 * The highest-priority local endpoint wins, so every pass of a scan picks the same listener when
 * several are advertised. A failure stays distinguishable from an empty window: a type that could
 * not be browsed or resolved makes the window unavailable rather than not observed.
 */
internal class AdbMdnsTally(private val kinds: List<AdbMdnsServiceKind>) {
    private val localServices = mutableMapOf<AdbMdnsServiceKind, AdbMdnsSnapshot>()
    private val failures = linkedMapOf<AdbMdnsServiceKind, String>()
    private val notBrowsing = mutableSetOf<AdbMdnsServiceKind>()
    private var permissionDenied: AdbMdnsSnapshot? = null

    /** True once a longer window can no longer change [snapshot]. */
    val decided: Boolean
        get() {
            if (permissionDenied != null) {
                return true
            }
            val browsing = kinds.filterNot(notBrowsing::contains)
            return browsing.isEmpty() || browsing.first() in localServices
        }

    fun discoveryFailed(kind: AdbMdnsServiceKind, detail: String, permission: Boolean) {
        notBrowsing += kind
        recordFailure(kind, detail, permission)
    }

    fun resolveFailed(kind: AdbMdnsServiceKind, detail: String, permission: Boolean) {
        recordFailure(kind, detail, permission)
    }

    fun localServiceResolved(kind: AdbMdnsServiceKind, serviceName: String?, address: String, port: Int) {
        localServices.putIfAbsent(
            kind,
            AdbMdnsSnapshot(
                state = AdbProbeState.OBSERVED,
                serviceKind = kind,
                serviceName = serviceName,
                address = address,
                port = port,
            ),
        )
    }

    fun snapshot(): AdbMdnsSnapshot {
        kinds.firstOrNull(localServices::containsKey)?.let { kind -> return localServices.getValue(kind) }
        permissionDenied?.let { return it }
        failures.entries.firstOrNull()?.let { (kind, detail) ->
            return AdbMdnsSnapshot(state = AdbProbeState.UNAVAILABLE, serviceKind = kind, detail = detail)
        }
        return AdbMdnsSnapshot(
            state = AdbProbeState.NOT_OBSERVED,
            detail = "No local ${kinds.joinToString(" or ") { it.serviceType }} service was resolved " +
                "during the discovery window.",
        )
    }

    private fun recordFailure(kind: AdbMdnsServiceKind, detail: String, permission: Boolean) {
        if (!permission) {
            failures.putIfAbsent(kind, detail)
        } else if (permissionDenied == null) {
            permissionDenied = AdbMdnsSnapshot(
                state = AdbProbeState.PERMISSION_REQUIRED,
                serviceKind = kind,
                detail = detail,
            )
        }
    }
}
