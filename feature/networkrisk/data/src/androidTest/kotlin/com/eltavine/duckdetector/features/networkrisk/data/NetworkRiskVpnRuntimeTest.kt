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

package com.eltavine.duckdetector.features.networkrisk.data

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.ConnectivityManager
import android.net.ProxyInfo
import android.net.VpnService
import android.os.IBinder
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.features.networkrisk.data.fixture.NetworkRiskVpnFixture
import com.eltavine.duckdetector.features.networkrisk.data.network.AndroidNetworkCollector
import com.eltavine.duckdetector.features.networkrisk.domain.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Opt-in fixtures for a dedicated emulator; VPN authorization must be granted before this suite. */
@RunWith(AndroidJUnit4::class)
class NetworkRiskVpnRuntimeTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val manager = context.getSystemService(ConnectivityManager::class.java)

    @Before fun requireDedicatedFixtureRun() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("runVpnFixture") == "true")
        assertNull("Authorize the test APK's VPN before running fixtures", VpnService.prepare(context))
        awaitSample { !it.defaultUsesVpn() && it.snapshot.defaultNetwork.value != null }
    }

    @Test fun vpnStartCallerExclusionAndStopPreserveCallingUidScope() = withFixture { control ->
        control.establish(context.packageName)
        val included = awaitSample { it.defaultUsesVpn() }
        assertEquals(DetectionSeverity.WARNING, NetworkRiskReport(NetworkRiskStage.READY, network = included).toDetectorStatus().severity)

        // Only the shell UID is allowed in this replacement VPN; the caller stays on its underlay.
        control.establish("com.android.shell")
        val excluded = awaitSample { !it.defaultUsesVpn() && it.snapshot.defaultNetwork.value != null }
        assertFalse(excluded.defaultUsesVpn())

        control.disconnect()
        awaitSample { !it.defaultUsesVpn() && it.snapshot.defaultNetwork.value != null }
    }

    @Test fun explicitProcessBindingSelectsUnderlayProxyWithoutChangingUidDefault() = withFixture { control ->
        val original = manager.boundNetworkForProcess
        val underlay = requireNotNull(manager.activeNetwork)
        try {
            control.establish(context.packageName, ProxyInfo.buildDirectProxy("127.0.0.1", 8888))
            val vpn = awaitSample { it.defaultUsesVpn() && it.snapshot.defaultProxy.value?.port == 8888 }
            assertEquals(ProxyKind.STATIC, vpn.snapshot.defaultProxy.value?.kind)
            assertTrue(manager.bindProcessToNetwork(underlay))
            val bound = awaitSample {
                it.defaultUsesVpn() && it.snapshot.boundNetwork.value == underlay.networkHandle &&
                    it.snapshot.defaultProxy.state == ObservationState.NOT_OBSERVED
            }
            assertEquals(underlay.networkHandle, bound.snapshot.boundNetwork.value)
            assertEquals(ProxySourceComparison.ALIGNED, bound.snapshot.proxySources?.comparison)
        } finally {
            assertTrue(manager.bindProcessToNetwork(original))
        }
    }

    private fun NetworkSampleWindow.defaultUsesVpn(): Boolean = snapshot.visibleNetworks.value.orEmpty().any {
        it.handle == snapshot.defaultNetwork.value && NetworkTransport.VPN in it.transports.value.orEmpty()
    }

    private fun awaitSample(predicate: (NetworkSampleWindow) -> Boolean): NetworkSampleWindow {
        val deadline = SystemClock.elapsedRealtime() + 10000
        do {
            val sample = AndroidNetworkCollector(context).collect()
            if (sample.consistency == SampleConsistency.REPEATED && predicate(sample)) return sample
            SystemClock.sleep(50)
        } while (SystemClock.elapsedRealtime() < deadline)
        error("Expected repeated network fixture state was not observed before deadline")
    }

    private fun withFixture(block: (NetworkRiskVpnFixture.Control) -> Unit) {
        val connected = CountDownLatch(1)
        var control: NetworkRiskVpnFixture.Control? = null
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                control = binder as NetworkRiskVpnFixture.Control
                connected.countDown()
            }
            override fun onServiceDisconnected(name: ComponentName) = Unit
        }
        val intent = Intent(context, NetworkRiskVpnFixture::class.java).setAction("networkrisk.test.CONTROL")
        assertTrue(context.bindService(intent, connection, Context.BIND_AUTO_CREATE))
        try {
            assertTrue("VPN fixture binding timed out", connected.await(10, TimeUnit.SECONDS))
            block(requireNotNull(control))
        } finally {
            control?.disconnect()
            context.unbindService(connection)
            awaitSample { !it.defaultUsesVpn() }
        }
    }
}
