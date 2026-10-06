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
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull

internal class AdbMdnsProbe(
    private val context: Context,
    private val protocolProbe: AdbProtocolProbe = AdbProtocolProbe(),
) {
    suspend fun collect(confirmProtocol: Boolean = false): AdbMdnsSnapshot {
        /*
         * Android 10 adbd already advertises legacy TCP ADB as _adb._tcp whenever setup_port()
         * enables a TCP listener. Android 11 adds _adb-tls-connect._tcp for the modern Wireless
         * Debugging TLSServer. Probe the service types that exist on the running platform instead
         * of treating all network ADB generations as the Android 11 TLS protocol.
         *
         * Android 10 tag android-10.0.0_r47, system/core commit
         * 1dea9a052b7f214c10a77d5ed6ffd3602722a817:
         * legacy service type is defined at adb_mdns.h line 20; setup_port() calls setup_mdns()
         * at daemon/main.cpp lines 182-187, and TCP port selection is at lines 243-258:
         * https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/adb_mdns.h#20
         * https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/daemon/main.cpp#182
         *
         * Android 11 tag android-11.0.0_r48, system/core commit
         * 348efca472d810d3152568913da41a081893a4e3:
         * adb-tls-connect is defined at lines 27-29 and included in the DNS-SD table at 79-82:
         * https://android.googlesource.com/platform/system/core/+/348efca472d810d3152568913da41a081893a4e3/adb/adb_mdns.h#27
         *
         * Android 16 tag android-16.0.0_r3, packages/modules/adb commit
         * cf10d3798f0847f89820381b541aedfd27a30375:
         * Wireless Debugging starts TlsServer first, then advertises that exact listener port as
         * the secure-connect service at daemon/adb_wifi.cpp lines 186-198:
         * https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/daemon/adb_wifi.cpp#186
         * register_adb_secure_connect_service() maps that port to
         * kADBSecureConnectServiceRefIndex at daemon/mdns.cpp lines 204-212:
         * https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/daemon/mdns.cpp#204
         */
        if (Build.VERSION.SDK_INT >= ANDROID_17_API &&
            context.checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            /*
             * Android 17 / API 37 applies Local Network Protection to NSD. Silent discovery without
             * ACCESS_LOCAL_NETWORK fails with FAILURE_PERMISSION_DENIED; an automatic detector must
             * not open the system service picker as a side effect of scanning.
             *
             * Android 17 tag android-17.0.0_r1, frameworks/base commit
             * 94b4c163b7dfe5ce3607f7bb8456f9573f7de57d:
             * ACCESS_LOCAL_NETWORK is declared dangerous at lines 2670-2677:
             * https://android.googlesource.com/platform/frameworks/base/+/94b4c163b7dfe5ce3607f7bb8456f9573f7de57d/core/res/AndroidManifest.xml#2670
             *
             * android-17.0.0_r1, packages/modules/Connectivity commit
             * 347fbd34b368d19f0d87e908ea101eed3601a731, NsdManager lines 1309-1317:
             * FAILURE_PERMISSION_DENIED is explicitly used for NSD discovery/resolution without
             * ACCESS_LOCAL_NETWORK:
             * https://android.googlesource.com/platform/packages/modules/Connectivity/+/347fbd34b368d19f0d87e908ea101eed3601a731/framework-t/src/android/net/nsd/NsdManager.java#1309
             */
            return AdbMdnsSnapshot(
                state = AdbProbeState.PERMISSION_REQUIRED,
                detail = "Android 17+ requires ACCESS_LOCAL_NETWORK for silent NsdManager discovery.",
            )
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val tls = discoverLocalService(
                serviceType = TLS_CONNECT_SERVICE,
                serviceKind = AdbMdnsServiceKind.TLS_CONNECT,
            )
            if (tls.state != AdbProbeState.NOT_OBSERVED) {
                return confirmProtocolIfNeeded(tls, confirmProtocol)
            }
        }

        val legacy = discoverLocalService(
            serviceType = LEGACY_TCP_SERVICE,
            serviceKind = AdbMdnsServiceKind.LEGACY_TCP,
        )
        return confirmProtocolIfNeeded(legacy, confirmProtocol)
    }

    private fun confirmProtocolIfNeeded(
        snapshot: AdbMdnsSnapshot,
        confirmProtocol: Boolean,
    ): AdbMdnsSnapshot {
        val address = snapshot.address
        val port = snapshot.port
        val kind = snapshot.serviceKind
        if (
            !confirmProtocol ||
            !snapshot.localServiceObserved ||
            address == null ||
            port == null ||
            kind == null
        ) {
            return snapshot
        }
        return snapshot.copy(
            protocol = protocolProbe.collect(
                address = address,
                port = port,
                serviceKind = kind,
            ),
        )
    }

    private suspend fun discoverLocalService(
        serviceType: String,
        serviceKind: AdbMdnsServiceKind,
    ): AdbMdnsSnapshot {
        val lastResolveFailure = AtomicReference<Int?>(null)
        return withTimeoutOrNull(DISCOVERY_TIMEOUT_MS) {
            awaitLocalService(serviceType, serviceKind, lastResolveFailure)
        } ?: lastResolveFailure.get()?.let { errorCode ->
            AdbMdnsSnapshot(
                state = AdbProbeState.UNAVAILABLE,
                serviceKind = serviceKind,
                detail = "NsdManager saw $serviceType but could not resolve it: $errorCode",
            )
        } ?: AdbMdnsSnapshot(
            state = AdbProbeState.NOT_OBSERVED,
            serviceKind = serviceKind,
            detail = "No local $serviceType service was resolved during the discovery window.",
        )
    }

    private suspend fun awaitLocalService(
        serviceType: String,
        serviceKind: AdbMdnsServiceKind,
        lastResolveFailure: AtomicReference<Int?>,
    ): AdbMdnsSnapshot = suspendCancellableCoroutine { continuation ->
            val nsd = context.getSystemService(NsdManager::class.java)
            val finished = AtomicBoolean(false)
            lateinit var discoveryListener: NsdManager.DiscoveryListener

            fun finish(snapshot: AdbMdnsSnapshot) {
                if (!finished.compareAndSet(false, true)) {
                    return
                }
                runCatching { nsd.stopServiceDiscovery(discoveryListener) }
                if (continuation.isActive) {
                    continuation.resume(snapshot)
                }
            }

            discoveryListener = object : NsdManager.DiscoveryListener {
                override fun onDiscoveryStarted(serviceType: String) = Unit

                override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                    finish(
                        AdbMdnsSnapshot(
                            state = if (isPermissionDenied(errorCode)) {
                                AdbProbeState.PERMISSION_REQUIRED
                            } else {
                                AdbProbeState.UNAVAILABLE
                            },
                            serviceKind = serviceKind,
                            detail = "NsdManager discovery for $serviceType failed to start: $errorCode",
                        ),
                    )
                }

                override fun onDiscoveryStopped(serviceType: String) = Unit

                override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) = Unit

                override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                    @Suppress("DEPRECATION")
                    nsd.resolveService(
                        serviceInfo,
                        object : NsdManager.ResolveListener {
                            override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                                if (isPermissionDenied(errorCode)) {
                                    finish(
                                        AdbMdnsSnapshot(
                                            state = AdbProbeState.PERMISSION_REQUIRED,
                                            serviceKind = serviceKind,
                                            detail = "NsdManager failed to resolve $serviceType: $errorCode",
                                        ),
                                    )
                                } else {
                                    /*
                                     * Discovery is a browsing session that continues delivering
                                     * onServiceFound/onServiceLost until explicitly stopped, while
                                     * resolveService() resolves one selected instance. A stale or
                                     * remote instance failing resolution therefore must not end
                                     * discovery before another local ADB instance can be found.
                                     *
                                     * android-17.0.0_r1, packages/modules/Connectivity commit
                                     * 347fbd34b368d19f0d87e908ea101eed3601a731:
                                     * discovery lifecycle lines 1979-1995:
                                     * https://android.googlesource.com/platform/packages/modules/Connectivity/+/347fbd34b368d19f0d87e908ea101eed3601a731/framework-t/src/android/net/nsd/NsdManager.java#1979
                                     * per-instance resolve contract lines 2172-2195:
                                     * https://android.googlesource.com/platform/packages/modules/Connectivity/+/347fbd34b368d19f0d87e908ea101eed3601a731/framework-t/src/android/net/nsd/NsdManager.java#2172
                                     */
                                    lastResolveFailure.set(errorCode)
                                }
                            }

                            override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                                val localAddress = resolvedLocalAddress(serviceInfo) ?: return
                                finish(
                                    AdbMdnsSnapshot(
                                        state = AdbProbeState.OBSERVED,
                                        serviceKind = serviceKind,
                                        serviceName = serviceInfo.serviceName,
                                        address = localAddress.hostAddress,
                                        port = serviceInfo.port,
                                    ),
                                )
                            }
                        },
                    )
                }

                override fun onServiceLost(serviceInfo: NsdServiceInfo) = Unit
            }

            continuation.invokeOnCancellation {
                if (finished.compareAndSet(false, true)) {
                    runCatching { nsd.stopServiceDiscovery(discoveryListener) }
                }
            }

            runCatching {
                nsd.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, discoveryListener)
            }.onFailure { failure ->
                finish(
                    AdbMdnsSnapshot(
                        state = AdbProbeState.UNAVAILABLE,
                        serviceKind = serviceKind,
                        detail = failure.message ?: "NsdManager discovery unavailable.",
                    ),
                )
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

    private companion object {
        const val LEGACY_TCP_SERVICE = "_adb._tcp"
        const val TLS_CONNECT_SERVICE = "_adb-tls-connect._tcp"
        const val ANDROID_17_API = 37
        const val DISCOVERY_TIMEOUT_MS = 1_500L
    }
}
