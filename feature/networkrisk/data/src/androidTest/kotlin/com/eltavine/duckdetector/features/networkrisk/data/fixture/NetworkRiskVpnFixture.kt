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

package com.eltavine.duckdetector.features.networkrisk.data.fixture

import android.content.Intent
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor

/** Test-only local TUN owner. No socket, packet forwarding, DNS query or remote server is used. */
class NetworkRiskVpnFixture : VpnService() {
    private var tunnel: ParcelFileDescriptor? = null
    private val control = Control()

    inner class Control : Binder() {
        @Synchronized
        fun establish(allowedPackage: String, proxy: ProxyInfo? = null) {
            val builder = Builder().setSession("Network Risk runtime fixture")
                .addAddress("192.0.2.1", 32).addRoute("0.0.0.0", 0)
                .addAllowedApplication(allowedPackage).allowBypass()
            if (proxy != null) builder.setHttpProxy(proxy)
            val replacement = requireNotNull(builder.establish()) { "VPN fixture has not been authorized" }
            tunnel?.close()
            tunnel = replacement
        }

        @Synchronized
        fun disconnect() {
            tunnel?.close()
            tunnel = null
        }
    }

    override fun onBind(intent: Intent): IBinder? =
        if (intent.action == SERVICE_INTERFACE) super.onBind(intent) else control

    override fun onDestroy() {
        control.disconnect()
        super.onDestroy()
    }

    override fun onRevoke() {
        control.disconnect()
        super.onRevoke()
    }
}
