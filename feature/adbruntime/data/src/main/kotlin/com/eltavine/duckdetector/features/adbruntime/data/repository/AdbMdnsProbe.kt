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

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import com.eltavine.duckdetector.features.adbruntime.domain.AdbMdnsServiceKind
import com.eltavine.duckdetector.features.adbruntime.domain.AdbMdnsSnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProbeState
import java.net.InetAddress
import java.net.NetworkInterface
import kotlin.coroutines.resume
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.SendChannel
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull

internal class AdbMdnsProbe(
    private val context: Context,
    private val protocolProbe: AdbProtocolProbe = AdbProtocolProbe(),
) {
    /**
     * Browses every ADB service type the platform defines in one window, _adb._tcp from Android 10
     * and _adb-tls-connect._tcp from Android 11, preferring the secure-connect listener
     * (EVIDENCE.md, "Network ADB mDNS").
     */
    suspend fun collect(confirmProtocol: Boolean = false): AdbMdnsSnapshot {
        if (Build.VERSION.SDK_INT >= ANDROID_17_API &&
            context.checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            // Silent discovery fails without the permission, and a scan never asks for it.
            return AdbMdnsSnapshot(
                state = AdbProbeState.PERMISSION_REQUIRED,
                detail = "Android 17+ requires ACCESS_LOCAL_NETWORK for silent NsdManager discovery.",
            )
        }
        val kinds = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            listOf(AdbMdnsServiceKind.TLS_CONNECT, AdbMdnsServiceKind.LEGACY_TCP)
        } else {
            listOf(AdbMdnsServiceKind.LEGACY_TCP)
        }
        val snapshot = discover(kinds)
        return if (confirmProtocol) withProtocol(snapshot) else snapshot
    }

    private fun withProtocol(snapshot: AdbMdnsSnapshot): AdbMdnsSnapshot {
        val address = snapshot.address
        val port = snapshot.port
        val kind = snapshot.serviceKind
        if (!snapshot.localServiceObserved || address == null || port == null || kind == null) {
            return snapshot
        }
        return snapshot.copy(protocol = protocolProbe.collect(address = address, port = port, serviceKind = kind))
    }

    private suspend fun discover(kinds: List<AdbMdnsServiceKind>): AdbMdnsSnapshot {
        val nsd = context.getSystemService(NsdManager::class.java)
            ?: return AdbMdnsSnapshot(state = AdbProbeState.UNAVAILABLE, detail = "NsdManager is unavailable.")
        val tally = AdbMdnsTally(kinds)
        val events = Channel<DiscoveryEvent>(Channel.UNLIMITED)
        val listeners = kinds.associateWith { kind -> discoveryListener(kind, events) }
        try {
            listeners.forEach { (kind, listener) ->
                runCatching {
                    nsd.discoverServices(kind.serviceType, NsdManager.PROTOCOL_DNS_SD, listener)
                }.onFailure { failure ->
                    tally.discoveryFailed(
                        kind = kind,
                        detail = failure.message ?: "NsdManager could not browse ${kind.serviceType}.",
                        permission = false,
                    )
                }
            }
            /*
             * Found services are resolved one at a time: NsdService fails a client's second
             * concurrent resolve with FAILURE_ALREADY_ACTIVE, so parallel resolves could lose this
             * device's instance to a remote one on the same LAN.
             */
            withTimeoutOrNull(DISCOVERY_TIMEOUT_MS) {
                while (!tally.decided) {
                    when (val event = events.receive()) {
                        is DiscoveryEvent.StartFailed -> tally.discoveryFailed(
                            kind = event.kind,
                            detail = "NsdManager discovery for ${event.kind.serviceType} failed to start: " +
                                event.errorCode,
                            permission = isPermissionDenied(event.errorCode),
                        )

                        is DiscoveryEvent.Found -> resolveInto(nsd, event, tally)
                    }
                }
            }
        } finally {
            events.close()
            listeners.values.forEach { listener -> runCatching { nsd.stopServiceDiscovery(listener) } }
        }
        return tally.snapshot()
    }

    private suspend fun resolveInto(nsd: NsdManager, found: DiscoveryEvent.Found, tally: AdbMdnsTally) {
        val kind = found.kind
        when (val outcome = nsd.resolve(found.service)) {
            is ResolveOutcome.Failed -> tally.resolveFailed(
                kind = kind,
                detail = "NsdManager saw ${kind.serviceType} but could not resolve it: " +
                    (outcome.errorCode?.toString() ?: outcome.message),
                permission = outcome.errorCode?.let(::isPermissionDenied) == true,
            )

            is ResolveOutcome.Resolved -> {
                val address = resolvedLocalAddress(outcome.service)?.hostAddress ?: return
                tally.localServiceResolved(kind, outcome.service.serviceName, address, outcome.service.port)
            }
        }
    }

    private fun discoveryListener(
        kind: AdbMdnsServiceKind,
        events: SendChannel<DiscoveryEvent>,
    ) = object : NsdManager.DiscoveryListener {
        override fun onDiscoveryStarted(serviceType: String) = Unit

        override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
            events.trySend(DiscoveryEvent.StartFailed(kind, errorCode))
        }

        override fun onDiscoveryStopped(serviceType: String) = Unit

        override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) = Unit

        override fun onServiceFound(serviceInfo: NsdServiceInfo) {
            events.trySend(DiscoveryEvent.Found(kind, serviceInfo))
        }

        override fun onServiceLost(serviceInfo: NsdServiceInfo) = Unit
    }

    @Suppress("DEPRECATION")
    private suspend fun NsdManager.resolve(service: NsdServiceInfo): ResolveOutcome =
        suspendCancellableCoroutine { continuation ->
            val listener = object : NsdManager.ResolveListener {
                override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                    if (continuation.isActive) continuation.resume(ResolveOutcome.Failed(errorCode, null))
                }

                override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                    if (continuation.isActive) continuation.resume(ResolveOutcome.Resolved(serviceInfo))
                }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                continuation.invokeOnCancellation { runCatching { stopServiceResolution(listener) } }
            }
            runCatching { resolveService(service, listener) }.onFailure { failure ->
                if (continuation.isActive) continuation.resume(ResolveOutcome.Failed(null, failure.message))
            }
        }

    private fun isPermissionDenied(errorCode: Int): Boolean =
        Build.VERSION.SDK_INT >= ANDROID_17_API &&
            errorCode == NsdManager.FAILURE_PERMISSION_DENIED

    @Suppress("DEPRECATION")
    private fun resolvedLocalAddress(serviceInfo: NsdServiceInfo): InetAddress? {
        val resolved = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            serviceInfo.hostAddresses
        } else {
            listOfNotNull(serviceInfo.host)
        }
        if (resolved.isEmpty()) {
            return null
        }
        val localAddresses = runCatching {
            NetworkInterface.getNetworkInterfaces()
                .asSequence()
                .flatMap { it.inetAddresses.asSequence() }
                .toSet()
        }.getOrDefault(emptySet())
        return resolved.firstOrNull(localAddresses::contains)
    }

    private sealed interface DiscoveryEvent {
        data class Found(val kind: AdbMdnsServiceKind, val service: NsdServiceInfo) : DiscoveryEvent

        data class StartFailed(val kind: AdbMdnsServiceKind, val errorCode: Int) : DiscoveryEvent
    }

    private sealed interface ResolveOutcome {
        data class Resolved(val service: NsdServiceInfo) : ResolveOutcome

        data class Failed(val errorCode: Int?, val message: String?) : ResolveOutcome
    }

    private companion object {
        const val ANDROID_17_API = 37
        const val DISCOVERY_TIMEOUT_MS = 1_500L
    }
}
